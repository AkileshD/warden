#!/usr/bin/env python3
"""
sidecar/interceptor.py — Warden Network Sidecar Interceptor

CONTRACT: This is the entry point for the warden-sidecar container.
It intercepts outbound network traffic from the jail using NFQUEUE.

Phase 2.5 update: provisional SYN acceptance + retroactive SNI evaluation.

The stateless Phase 2 callback evaluated every packet independently.
Hostname-based ALLOW rules could never fire because the first packet of a
TLS connection (the TCP SYN) carries no payload and therefore no SNI —
it always fell through to default-deny before the ClientHello arrived.

Phase 2.5 adds two new code paths inside build_callback (all other traffic
continues through the original stateless path unchanged):

  PATH A — Provisional SYN acceptance
    Condition: packet is a bare TCP SYN AND the destination port has at
    least one hostname-based ALLOW rule in policy.yaml.
    Action:    accept the SYN immediately (without logging) and call
               tracker.track() so the connection is remembered long enough
               for the ClientHello to arrive.
    WHY no log yet: nothing has been decided at SYN time. The log event is
    emitted in Path B once the SNI is evaluated.

  PATH B — ClientHello resolution
    Condition: PacketParser successfully extracts a hostname_or_sni from
               the packet AND tracker.is_pending() is True for this 4-tuple.
    Action:    tracker.resolve() -> evaluate hostname via NetworkInspector ->
               ALLOW (accept + log) or BLOCK (drop + log). Log reason strings
               distinguish Path B ALLOWs and BLOCKs from stateless ones.

    RISK: On a Path B BLOCK, only the ClientHello packet itself is dropped.
      The TCP SYN/handshake was already accepted (Path A), so without a TCP
      RST the underlying connection may remain half-open or the client may
      retry. This does not terminate the TCP session cleanly. Full retroactive
      termination via RST injection is deliberately out of scope for this step
      (Step 3). Do NOT add RST logic here — get that reviewed as Step 3 first.

  SWEEP — Per-packet TTL sweep
    Before processing each packet, sweep_expired() is called on the tracker.
    Entries that expire unresolved (SYN sent, no ClientHello within TTL) are
    logged as BLOCK events with a reason distinct from Path B BLOCKs. No
    packet drop is possible for expired entries (no packet is in hand).
"""

import os
import sys
import argparse
import subprocess
import atexit
import yaml
import json
import socket
import time
from typing import Any, Dict, List, Optional

try:
    import netfilterqueue  # type: ignore
except ImportError:
    pass

from daemon.parser.packet_parser import PacketParser, ParsedNetworkAction
from daemon.inspectors.network_inspector import NetworkInspector
from daemon.rules.engine import RuleEngine
from daemon.inspectors.base import Decision, Verdict

from sidecar.conntrack import (
    PendingConnectionTracker,
    DEFAULT_TTL_SECONDS,
    BlockedConnectionTracker,
    DEFAULT_BLOCKED_TTL_SECONDS,
)
from sidecar.rst_injector import build_rst_packet, send_rst

POLICY_PATH = os.environ.get("WARDEN_POLICY_PATH", "daemon/rules/policy.yaml")
WARDEN_UDP_HOST = os.environ.get("WARDEN_UDP_HOST", "host.docker.internal")
WARDEN_UDP_PORT = int(os.environ.get("WARDEN_UDP_PORT", 5005))
WARDEN_TOKEN_PATH = os.environ.get("WARDEN_TOKEN_PATH", "/tmp/warden_ipc/token.txt")
NFQUEUE_NUM = 0

# Reason strings used in ledger events — kept as constants so tests can
# assert against them without hardcoding free-form strings.
REASON_PROVISIONAL_BLOCK_TTL = (
    "provisional connection expired — no ClientHello observed within TTL"
)
REASON_PROVISIONAL_ALLOW_SNI = "provisional ALLOW — SNI matched allowlist rule"
REASON_PROVISIONAL_BLOCK_SNI = "provisional BLOCK — SNI did not match any ALLOW rule"


# ── Pure helpers (no I/O, fully unit-testable) ─────────────────────────────────

def _is_syn(parsed: ParsedNetworkAction) -> bool:
    """
    Return True if parsed represents a bare TCP SYN packet.

    A SYN packet has:
      - protocol == "TCP"
      - no TCP payload (hostname_or_sni is None)

    WHY check hostname_or_sni is None rather than inspecting TCP flags directly:
      PacketParser does not currently expose TCP flags as a field on
      ParsedNetworkAction. Checking for the absence of a hostname/payload is the
      correct proxy: a ClientHello always sets hostname_or_sni; a bare SYN never
      does. This check is sufficient for the Phase 2.5 use case.

    WHY this is a module-level function (not a method on ParsedNetworkAction):
      It answers a sidecar-specific routing question (should this SYN be tracked?),
      not a general property of the parsed action. Keeping it here avoids leaking
      sidecar policy logic into the parser layer.
    """
    return parsed.protocol == "TCP" and parsed.hostname_or_sni is None


def _has_hostname_rules(dst_port: int, network_rules: List[Dict[str, Any]]) -> bool:
    """
    Return True if any rule in network_rules has a 'hostname' match key for
    dst_port (or for any port, if the rule has no dst_port restriction).

    This is the gate for Path A: we only provision-accept SYNs if there is
    at least one hostname-based rule that could potentially fire for this port.
    If the port has only IP/CIDR rules (no hostname key), the stateless path
    already handles it correctly — no tracking needed.

    WHY scan all rules rather than pre-build an index:
      network_rules is a small list (< 20 entries in practice). A linear scan
      at packet time is negligible. Pre-building an index would need to be
      invalidated on policy hot-reload — not worth the complexity.

    WHY 'hostname' key specifically (not 'dst_ip'):
      The Phase 2.5 tracking primitive exists solely to bridge the SYN->ClientHello
      gap for hostname-based rules. IP rules already work statelessly (no SNI needed
      to match against a CIDR). Tracking SYNs destined for IP-only rules would add
      cost with zero benefit.
    """
    for rule in network_rules:
        match = rule.get("match", {})
        if "hostname" not in match:
            continue
        # Port check: rule applies to this port if dst_port key is absent (any port)
        # or if dst_port is in the rule's port list.
        rule_ports = match.get("dst_port", [])
        if not rule_ports:
            return True  # No port restriction — applies to all ports
        if dst_port in rule_ports:
            return True
    return False


def _make_event_payload(
    verdict: Verdict,
    parsed: ParsedNetworkAction,
    token: str,
    ts: Optional[float] = None,
) -> Dict[str, Any]:
    """
    Build the UDP IPC event payload dict for a single network event.

    Extracted from the inline JSON construction in the original callback so
    it can be reused for both live-packet events and sweep-expired synthetic
    events without duplicating the field layout.

    WHY separate function: the sweep-expired path needs to emit events for
    connections that have already expired (no live packet in hand). Having
    one place that constructs the payload dict means field-layout changes
    are made in one location.
    """
    return {
        "timestamp": ts if ts is not None else time.time(),
        "token": token,
        "verdict": {
            "decision": verdict.decision.value,
            "reason": verdict.reason,
            "source_inspector": verdict.source_inspector,
            "confidence": verdict.confidence,
        },
        "parsed_action": {
            "dst_ip": parsed.dst_ip,
            "dst_port": parsed.dst_port,
            "protocol": parsed.protocol,
            "hostname_or_sni": parsed.hostname_or_sni,
            "direction": parsed.direction,
            "raw_input": parsed.raw_input,
        },
    }


# ── Environment / iptables helpers ─────────────────────────────────────────────

def verify_environment() -> bool:
    """Verify the container environment before attempting NFQUEUE work."""
    ok = True
    token_dir = os.path.dirname(WARDEN_TOKEN_PATH)
    if not os.path.isdir(token_dir):
        print(f"[warden-sidecar] ERROR: IPC directory {token_dir!r} does not exist.", file=sys.stderr, flush=True)
        ok = False

    try:
        import netfilterqueue  # type: ignore # noqa: F401
    except ImportError as e:
        print(f"[warden-sidecar] ERROR: cannot import netfilterqueue: {e}", file=sys.stderr, flush=True)
        ok = False
    except OSError as e:
        print(f"[warden-sidecar] ERROR: netfilterqueue import raised OSError: {e}", file=sys.stderr, flush=True)
        ok = False

    return ok


def setup_iptables(queue_num: int) -> None:
    """
    Insert iptables rule to redirect traffic to NFQUEUE.

    WHY OUTPUT (not FORWARD): The sidecar shares the jail's network namespace
    (`network_mode: "service:jail"` in docker-compose.yml). From the perspective
    of this shared namespace, packets generated by the jail's processes originate
    locally. They therefore traverse the OUTPUT chain. The FORWARD chain only
    applies to packets being routed *through* the namespace from one interface
    to another, which is not what the jail is doing.
    """
    print(f"[warden-sidecar] Inserting iptables rule on OUTPUT chain for queue {queue_num}...", flush=True)
    subprocess.run(
        ["iptables", "-I", "OUTPUT", "-j", "NFQUEUE", "--queue-num", str(queue_num)],
        check=True
    )
    # Exempt our own UDP IPC traffic from being intercepted!
    subprocess.run(
        ["iptables", "-I", "OUTPUT", "-p", "udp", "--dport", str(WARDEN_UDP_PORT), "-j", "ACCEPT"],
        check=True
    )


def teardown_iptables(queue_num: int) -> None:
    """Remove the iptables rule on exit."""
    print(f"[warden-sidecar] Removing iptables rule for queue {queue_num}...", flush=True)
    subprocess.run(
        ["iptables", "-D", "OUTPUT", "-p", "udp", "--dport", str(WARDEN_UDP_PORT), "-j", "ACCEPT"],
        check=False
    )
    subprocess.run(
        ["iptables", "-D", "OUTPUT", "-j", "NFQUEUE", "--queue-num", str(queue_num)],
        check=False  # Ignore errors if rule is already gone
    )


# ── Callback factory ───────────────────────────────────────────────────────────

def build_callback(
    parser: PacketParser,
    inspector: NetworkInspector,
    engine: RuleEngine,
    network_rules: Optional[List[Dict[str, Any]]] = None,
    tracker: Optional[PendingConnectionTracker] = None,
    blocked_tracker: Optional[BlockedConnectionTracker] = None,
):
    """
    Factory to build the NFQUEUE packet callback with closed-over dependencies.

    Phase 2.5 additions vs. Phase 2:
      - network_rules: needed by _has_hostname_rules() to decide whether to
        track a SYN. If None, defaults to an empty list (no hostname rules
        -> stateless path always taken, full backward compatibility).
      - tracker: PendingConnectionTracker instance. If None, a new one is
        created. Callers may pass an existing instance for testing.

    WHY factory pattern (not a class):
      The original design used a closure to avoid threading state through
      every call site. Keeping the factory pattern preserves that design and
      makes the Phase 2.5 additions additive, not structural.

    CONTRACT: The returned callback has the signature:
      packet_callback(packet) -> None
    where `packet` exposes .get_payload() -> bytes, .accept(), and .drop().
    This matches the netfilterqueue API and the MockPacket used in tests.
    """
    _network_rules: List[Dict[str, Any]] = network_rules if network_rules is not None else []
    _tracker: PendingConnectionTracker = tracker if tracker is not None else PendingConnectionTracker()
    _block_tracker: BlockedConnectionTracker = blocked_tracker if blocked_tracker is not None else BlockedConnectionTracker()
    _cached_token: Optional[str] = None

    def get_token() -> Optional[str]:
        nonlocal _cached_token
        if _cached_token is None:
            try:
                with open(WARDEN_TOKEN_PATH, "r") as f:
                    _cached_token = f.read().strip()
            except OSError:
                pass
        return _cached_token

    def _send_event(verdict: Verdict, parsed: ParsedNetworkAction) -> None:
        """Send one network event to the daemon via UDP IPC. Swallows all errors."""
        try:
            token = get_token()
            if not token:
                raise ValueError(f"Token file not found or empty at {WARDEN_TOKEN_PATH}")
            payload = _make_event_payload(verdict, parsed, token)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.sendto(json.dumps(payload).encode("utf-8"), (WARDEN_UDP_HOST, WARDEN_UDP_PORT))
        except Exception as e:
            print(f"[warden-sidecar] Warning: failed to send event to UDP socket: {e}", file=sys.stderr)

    def _sweep_and_log() -> None:
        """
        Sweep expired tracker entries and emit a BLOCK log event for each.

        WHY log expired entries: a SYN that never saw a ClientHello within TTL
        indicates either (a) non-TLS traffic on a hostname-ruled port, (b) a
        stalled or abandoned handshake. Both are security-relevant events.
        Logging them as BLOCK (with a distinct reason string) lets the operator
        distinguish TTL-expiry BLOCKs from SNI-mismatch BLOCKs in the ledger.

        WHY no packet.drop() here: there is no live packet in hand for an expired
        entry. The client's connection is already in an undefined state. RST
        injection to terminate it cleanly is Step 3.
        """
        now = time.time()
        expired = _tracker.sweep_expired(now)
        for entry in expired:
            src_ip, src_port, dst_ip, dst_port = entry.conn_key
            synthetic_parsed = ParsedNetworkAction(
                binary="<network>",
                raw_input=f"TCP {dst_ip}:{dst_port} (provisional-expired)",
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol="TCP",
                hostname_or_sni=None,
                direction="outbound",
            )
            expired_verdict = Verdict(
                decision=Decision.BLOCK,
                reason=REASON_PROVISIONAL_BLOCK_TTL,
                source_inspector="ConnTrack",
            )
            _send_event(expired_verdict, synthetic_parsed)
            print(
                f"[warden-sidecar] Expired provisional connection {src_ip}:{src_port} -> "
                f"{dst_ip}:{dst_port} — logged BLOCK (no ClientHello within TTL)",
                flush=True,
            )

    def packet_callback(packet) -> None:
        # ── Per-packet sweep ──────────────────────────────────────────────────
        # WHY before parse: sweep on every packet so expired entries are cleaned
        # promptly. The overhead is a dict scan over a tiny list (see conntrack.py
        # RISK note). Running sweep before the decision avoids logging an expired
        # entry at the same time as processing a new packet for the same key.
        _sweep_and_log()
        _block_tracker.sweep_expired(time.time())

        # ── 1. Parse ──────────────────────────────────────────────────────────
        raw_bytes = packet.get_payload()
        try:
            parsed = parser.parse(raw_bytes)
        except Exception:
            # If we absolutely cannot parse it, drop it as malformed.
            packet.drop()
            return

        # Real 4-tuple conn_key: (src_ip, src_port, dst_ip, dst_port).
        # PacketParser now exposes src_ip and src_port from the IP/TCP/UDP
        # layers, so this key uniquely identifies a TCP flow even when two
        # connections share the same destination (different ephemeral src_port).
        conn_key = (parsed.src_ip, parsed.src_port, parsed.dst_ip, parsed.dst_port)

        # ── POST-BLOCK CONTAINMENT ───────────────────────────────────────────
        if _block_tracker.is_blocked(conn_key):
            packet.drop()
            return

        # ── PATH A — Provisional SYN acceptance ──────────────────────────────
        if _is_syn(parsed) and _has_hostname_rules(parsed.dst_port, _network_rules):
            # WHY accept without logging: the connection is pending evaluation.
            # The ledger event is emitted in Path B once the SNI is known.
            # If no ClientHello arrives within TTL, _sweep_and_log() emits
            # the BLOCK event.
            _tracker.track(
                conn_key=conn_key,
                dst_port=parsed.dst_port,
                expires_at=time.time() + DEFAULT_TTL_SECONDS,
            )
            print(
                f"[warden-sidecar] Path A: SYN to {parsed.dst_ip}:{parsed.dst_port} "
                f"provisionally accepted — tracking for SNI",
                flush=True,
            )
            packet.accept()
            return

        # ── PATH B — ClientHello on a tracked connection ──────────────────────
        if parsed.hostname_or_sni is not None and _tracker.is_pending(conn_key):
            entry = _tracker.resolve(conn_key)
            if entry is not None:
                # Evaluate the SNI through the full inspector+engine chain.
                verdict = inspector.inspect(parsed)
                final_verdict = engine.evaluate(parsed, [verdict] if verdict else [])

                if final_verdict.decision == Decision.ALLOW:
                    result_verdict = Verdict(
                        decision=Decision.ALLOW,
                        reason=REASON_PROVISIONAL_ALLOW_SNI,
                        source_inspector="ConnTrack+NetworkInspector",
                    )
                    _send_event(result_verdict, parsed)
                    print(
                        f"[warden-sidecar] Path B ALLOW: {parsed.hostname_or_sni} "
                        f"matched allowlist rule",
                        flush=True,
                    )
                    packet.accept()
                else:
                    # RISK: Only this ClientHello packet is dropped. The TCP
                    # handshake (SYN/SYN-ACK/ACK) has already completed because the
                    # SYN was provisionally accepted in Path A. Dropping only the
                    # ClientHello does not terminate the TCP connection. We inject
                    # a TCP RST below to tear it down.
                    # HOWEVER, RST delivery itself is unconfirmable by design (no
                    # ACK-of-RST exists in TCP). Therefore, we also register this
                    # connection in the post-BLOCK containment tracker to prevent
                    # any further data flow on this connection regardless of RST
                    # delivery success.
                    packet.drop()

                    # Phase 2.5 Step 4: Post-BLOCK containment
                    _block_tracker.block(conn_key, time.time() + DEFAULT_BLOCKED_TTL_SECONDS)

                    # Phase 2.5 Step 3: RST injection
                    rst_bytes = build_rst_packet(
                        src_ip=parsed.src_ip,
                        src_port=parsed.src_port,
                        dst_ip=parsed.dst_ip,
                        dst_port=parsed.dst_port,
                        seq=parsed.seq,
                        ack=parsed.ack,
                    )
                    rst_success = send_rst(rst_bytes, dst_ip=parsed.src_ip)
                    rst_status = "(RST succeeded)" if rst_success else "(RST failed)"

                    result_verdict = Verdict(
                        decision=Decision.BLOCK,
                        reason=f"{REASON_PROVISIONAL_BLOCK_SNI} {rst_status}",
                        source_inspector="ConnTrack+NetworkInspector",
                    )
                    _send_event(result_verdict, parsed)
                    print(
                        f"[warden-sidecar] Path B BLOCK: {parsed.hostname_or_sni} "
                        f"not on allowlist — ClientHello dropped {rst_status}",
                        flush=True,
                    )
                return

        # ── STATELESS PATH — all other traffic (unchanged from Phase 2) ───────
        # Non-SYN packets to non-hostname-ruled ports, inbound responses, and
        # any packet that fell through the A/B conditions above all take this path.
        # WHY unchanged: Phase 2.5 must not alter existing IP-rule enforcement.

        # 2. Inspect
        verdict = inspector.inspect(parsed)

        # 3. Evaluate
        final_verdict = engine.evaluate(parsed, [verdict] if verdict else [])

        # 4. Log via UDP IPC
        _send_event(final_verdict, parsed)

        # 5. Enforce
        if final_verdict.decision == Decision.ALLOW:
            packet.accept()
        else:
            packet.drop()

    return packet_callback


# ── Entry point ────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true", help="Read packet bytes from stdin instead of NFQUEUE")
    args = parser.parse_args()

    if not args.dry_run and not verify_environment():
        print("[warden-sidecar] environment checks FAILED", file=sys.stderr, flush=True)
        sys.exit(1)

    print("[warden-sidecar] Loading components...", flush=True)

    with open(POLICY_PATH, "r") as f:
        policy_doc = yaml.safe_load(f)
    network_rules = policy_doc.get("network_rules", [])

    # Instantiate the 3 pillars of the interception loop
    packet_parser = PacketParser()
    net_inspector = NetworkInspector(network_rules=network_rules)
    engine = RuleEngine(policy_path=POLICY_PATH)

    # Phase 2.5: create the connection tracker and pass network_rules through.
    tracker = PendingConnectionTracker()

    callback = build_callback(
        packet_parser,
        net_inspector,
        engine,
        network_rules=network_rules,
        tracker=tracker,
    )

    if args.dry_run:
        print("[warden-sidecar] Running in --dry-run mode", flush=True)
        raw_bytes = sys.stdin.buffer.read()
        if not raw_bytes:
            print("No bytes received on stdin.", file=sys.stderr)
            sys.exit(0)

        class MockPacket:
            def __init__(self, payload): self._payload = payload
            def get_payload(self): return self._payload
            def accept(self): print("ACTION: ACCEPT")
            def drop(self): print("ACTION: DROP")

        callback(MockPacket(raw_bytes))
        sys.exit(0)

    # Full NFQUEUE mode
    setup_iptables(queue_num=NFQUEUE_NUM)
    atexit.register(teardown_iptables, NFQUEUE_NUM)

    nfqueue = netfilterqueue.NetfilterQueue()
    nfqueue.bind(NFQUEUE_NUM, callback)

    print(f"[warden-sidecar] Listening on NFQUEUE {NFQUEUE_NUM}...", flush=True)
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print("\n[warden-sidecar] Shutting down...")
    finally:
        nfqueue.unbind()


if __name__ == "__main__":
    main()
