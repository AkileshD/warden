"""
tests/test_interceptor_conntrack.py — Tests for Phase 2.5 conntrack wiring
in sidecar/interceptor.py.

These tests verify the three new code paths added in Phase 2.5 Step 2:
  - Path A: bare SYN to a hostname-ruled port is provisionally accepted and
            tracked, with no ledger event emitted.
  - Path B: ClientHello on a tracked connection is resolved and evaluated;
            ALLOW or BLOCK is enforced and logged with distinct reason strings.
  - SWEEP:  expired tracker entries produce BLOCK log events with the TTL-expiry
            reason string, distinct from Path B BLOCK reason strings.
  - STATIC: pure-IP-ruled port traffic continues through the stateless path
            unchanged (no tracking, verdict-driven accept/drop).

No Docker, NFQUEUE, or running daemon required.  All packet bytes are
constructed with Scapy (same pattern as test_packet_parser.py). The UDP
send function is replaced by a mock so no actual socket is opened.

WHY this test file does not import from test_packet_parser.py:
  Shared test helpers across test files create implicit coupling and make
  individual test files harder to run in isolation. The helpers are small
  enough to duplicate here — they are copied verbatim to preserve exact
  bit-level correctness.
"""

import struct
import time
from unittest.mock import MagicMock, call, patch
from typing import Any, Dict, List

import pytest
from scapy.all import IP, TCP, UDP, Raw

from daemon.parser.packet_parser import PacketParser
from daemon.inspectors.network_inspector import NetworkInspector
from daemon.rules.engine import RuleEngine
from daemon.inspectors.base import Decision

from sidecar.conntrack import PendingConnectionTracker, DEFAULT_TTL_SECONDS
from sidecar.interceptor import (
    build_callback,
    _is_syn,
    _has_hostname_rules,
    REASON_PROVISIONAL_BLOCK_TTL,
    REASON_PROVISIONAL_ALLOW_SNI,
    REASON_PROVISIONAL_BLOCK_SNI,
)


# ---------------------------------------------------------------------------
# Scapy packet helpers (mirrored from test_packet_parser.py)
# ---------------------------------------------------------------------------

JAIL_SRC_IP = "192.168.1.10"   # RFC1918 — parsed as outbound by PacketParser
ALLOWED_HOST = "api.openai.com"  # present in policy.yaml hostname ALLOW rules
BLOCKED_HOST  = "malicious.example.net"  # not in any ALLOW rule
HOSTNAME_PORT = 443             # port with hostname rules in policy.yaml
IP_ONLY_PORT  = 80              # port with no hostname rules in policy.yaml
ALLOWED_IP    = "104.20.23.154" # IP explicitly on the allowlist in policy.yaml


def _make_tcp_syn(dst_ip: str = "93.184.216.34", dst_port: int = 443) -> bytes:
    """Bare TCP SYN packet with no payload."""
    pkt = IP(src=JAIL_SRC_IP, dst=dst_ip) / TCP(sport=54321, dport=dst_port, flags="S")
    return bytes(pkt)


def _make_tcp_with_sni(sni: str, dst_ip: str = "93.184.216.34", dst_port: int = 443) -> bytes:
    """TCP packet carrying a TLS ClientHello with the given SNI."""
    payload = _make_tls_client_hello(sni)
    pkt = IP(src=JAIL_SRC_IP, dst=dst_ip) / TCP(sport=54321, dport=dst_port) / Raw(load=payload)
    return bytes(pkt)


def _make_tcp_ip_only(dst_ip: str = ALLOWED_IP, dst_port: int = IP_ONLY_PORT) -> bytes:
    """Plain TCP packet to a pure-IP destination with no payload."""
    pkt = IP(src=JAIL_SRC_IP, dst=dst_ip) / TCP(sport=54322, dport=dst_port, flags="S")
    return bytes(pkt)


def _make_tls_client_hello(sni: str) -> bytes:
    """
    Construct a minimal TLS 1.2 ClientHello with a single SNI extension.
    Copied from test_packet_parser.py's make_tls_client_hello_payload().
    """
    sni_bytes = sni.encode("ascii")
    sni_name_len = len(sni_bytes)

    sni_ext_body = (
        struct.pack("!H", sni_name_len + 3)  # SNI list length
        + b"\x00"                             # name type: host_name
        + struct.pack("!H", sni_name_len)     # name length
        + sni_bytes
    )
    sni_extension = struct.pack("!HH", 0x0000, len(sni_ext_body)) + sni_ext_body

    client_version = b"\x03\x03"
    random_bytes   = b"\x00" * 32
    session_id     = b"\x00"
    cipher_suites  = b"\x00\x02\x00\x2F"
    compression    = b"\x01\x00"

    extensions_len = struct.pack("!H", len(sni_extension))
    hello_body = (
        client_version + random_bytes + session_id
        + cipher_suites + compression + extensions_len + sni_extension
    )

    hello_len = len(hello_body)
    handshake_header = bytes([0x01]) + struct.pack("!I", hello_len)[1:]
    handshake_message = handshake_header + hello_body

    record_header = (
        b"\x16"
        + b"\x03\x03"
        + struct.pack("!H", len(handshake_message))
    )
    return record_header + handshake_message


# ---------------------------------------------------------------------------
# Shared fixtures and MockPacket
# ---------------------------------------------------------------------------

class MockPacket:
    """Minimal stand-in for a netfilterqueue Packet object."""
    def __init__(self, raw_bytes: bytes):
        self._payload = raw_bytes
        self.accepted = False
        self.dropped  = False

    def get_payload(self) -> bytes:
        return self._payload

    def accept(self) -> None:
        self.accepted = True

    def drop(self) -> None:
        self.dropped = True


POLICY_PATH = "daemon/rules/policy.yaml"


def _make_components():
    """Build real PacketParser, NetworkInspector, RuleEngine from policy.yaml."""
    import yaml
    with open(POLICY_PATH) as f:
        policy_doc = yaml.safe_load(f)
    network_rules = policy_doc.get("network_rules", [])

    parser    = PacketParser()
    inspector = NetworkInspector(network_rules=network_rules)
    engine    = RuleEngine(policy_path=POLICY_PATH)
    return parser, inspector, engine, network_rules


# ---------------------------------------------------------------------------
# Tests for pure helpers
# ---------------------------------------------------------------------------

class TestIsSyn:
    """Unit tests for the _is_syn() pure helper."""

    def test_bare_tcp_syn_is_syn(self):
        raw = _make_tcp_syn()
        parsed = PacketParser.parse(raw)
        assert _is_syn(parsed)

    def test_tcp_with_tls_payload_is_not_syn(self):
        raw = _make_tcp_with_sni(ALLOWED_HOST)
        parsed = PacketParser.parse(raw)
        assert not _is_syn(parsed)

    def test_udp_packet_is_not_syn(self):
        pkt = IP(src=JAIL_SRC_IP, dst="8.8.8.8") / UDP(sport=11111, dport=53)
        parsed = PacketParser.parse(bytes(pkt))
        assert not _is_syn(parsed)


class TestHasHostnameRules:
    """Unit tests for the _has_hostname_rules() pure helper."""

    RULES_WITH_HOSTNAME = [
        {"match": {"hostname": ["api.openai.com"], "dst_port": [443]}, "action": "allow"},
    ]
    RULES_IP_ONLY = [
        {"match": {"dst_ip": ["10.0.0.0/8"]}, "action": "allow"},
    ]
    RULES_HOSTNAME_ANY_PORT = [
        {"match": {"hostname": ["api.openai.com"]}, "action": "allow"},
    ]

    def test_hostname_rule_for_matching_port_returns_true(self):
        assert _has_hostname_rules(443, self.RULES_WITH_HOSTNAME)

    def test_hostname_rule_for_non_matching_port_returns_false(self):
        assert not _has_hostname_rules(80, self.RULES_WITH_HOSTNAME)

    def test_ip_only_rules_return_false(self):
        assert not _has_hostname_rules(443, self.RULES_IP_ONLY)

    def test_empty_rules_return_false(self):
        assert not _has_hostname_rules(443, [])

    def test_hostname_rule_with_no_port_restriction_matches_any_port(self):
        assert _has_hostname_rules(8080, self.RULES_HOSTNAME_ANY_PORT)
        assert _has_hostname_rules(443,  self.RULES_HOSTNAME_ANY_PORT)


# ---------------------------------------------------------------------------
# Tests for build_callback (Path A, B, Sweep, Stateless)
# ---------------------------------------------------------------------------

class TestPathA:
    """
    Path A: bare SYN to a hostname-ruled port is provisionally accepted and
    tracked. No ledger event is emitted.
    """

    def test_syn_to_hostname_port_is_accepted(self):
        parser, inspector, engine, network_rules = _make_components()
        tracker = PendingConnectionTracker()
        sent_events: List[Dict] = []

        with patch("sidecar.interceptor.WARDEN_TOKEN_PATH", "/dev/null"):
            callback = build_callback(
                parser, inspector, engine,
                network_rules=network_rules,
                tracker=tracker,
            )
            # Inject a fake token so _send_event doesn't silently discard.
            # (We don't expect any send here, but ensure the token path doesn't mask errors.)
            with patch("builtins.open", side_effect=OSError("no token")):
                pkt = MockPacket(_make_tcp_syn(dst_port=HOSTNAME_PORT))
                callback(pkt)

        assert pkt.accepted, "SYN to hostname-ruled port must be provisionally accepted"
        assert not pkt.dropped

    def test_syn_to_hostname_port_is_tracked(self):
        parser, inspector, engine, network_rules = _make_components()
        tracker = PendingConnectionTracker()

        with patch("sidecar.interceptor.WARDEN_TOKEN_PATH", "/dev/null"):
            with patch("builtins.open", side_effect=OSError("no token")):
                callback = build_callback(
                    parser, inspector, engine,
                    network_rules=network_rules,
                    tracker=tracker,
                )
                pkt = MockPacket(_make_tcp_syn(dst_port=HOSTNAME_PORT))
                callback(pkt)

        assert len(tracker) == 1, "Tracker must have exactly one entry after SYN"

    def test_syn_to_hostname_port_emits_no_ledger_event(self):
        """No UDP event must be sent for a provisional SYN — nothing decided yet."""
        parser, inspector, engine, network_rules = _make_components()
        tracker = PendingConnectionTracker()
        sent_payloads: List[bytes] = []

        # Patch socket.socket to capture any sends
        mock_sock = MagicMock()
        mock_sock.__enter__ = lambda s: mock_sock
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_sock.sendto = lambda data, addr: sent_payloads.append(data)

        with patch("sidecar.interceptor.WARDEN_TOKEN_PATH", "/dev/null"), \
             patch("socket.socket", return_value=mock_sock), \
             patch("builtins.open", side_effect=OSError("no token")):
            callback = build_callback(
                parser, inspector, engine,
                network_rules=network_rules,
                tracker=tracker,
            )
            pkt = MockPacket(_make_tcp_syn(dst_port=HOSTNAME_PORT))
            callback(pkt)

        assert sent_payloads == [], "No ledger event should be sent for a provisional SYN"

    def test_syn_to_ip_only_port_not_tracked(self):
        """SYN to a port with no hostname rules goes through the stateless path, not tracked."""
        parser, inspector, engine, network_rules = _make_components()
        tracker = PendingConnectionTracker()

        with patch("sidecar.interceptor.WARDEN_TOKEN_PATH", "/dev/null"), \
             patch("socket.socket"), \
             patch("builtins.open", side_effect=OSError("no token")):
            callback = build_callback(
                parser, inspector, engine,
                network_rules=network_rules,
                tracker=tracker,
            )
            # Port 80 has no hostname rules in policy.yaml
            pkt = MockPacket(_make_tcp_syn(dst_port=IP_ONLY_PORT))
            callback(pkt)

        assert len(tracker) == 0, "SYN to IP-only port must not be tracked"


class TestPathB:
    """
    Path B: ClientHello on a tracked connection is resolved and evaluated.
    ALLOW -> accept + log ALLOW event with REASON_PROVISIONAL_ALLOW_SNI.
    BLOCK -> drop  + log BLOCK event with REASON_PROVISIONAL_BLOCK_SNI.
    """

    def _run_syn_then_client_hello(self, sni: str, dst_ip: str = "93.184.216.34"):
        """Helper: run Path A (SYN) then Path B (ClientHello), return packet + sent events."""
        parser, inspector, engine, network_rules = _make_components()
        tracker = PendingConnectionTracker()
        sent_payloads: List[bytes] = []

        mock_sock = MagicMock()
        mock_sock.__enter__ = lambda s: mock_sock
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_sock.sendto = lambda data, addr: sent_payloads.append(data)

        # Provide a fake token by patching open specifically for the token file.
        import io
        def _fake_open(path, *args, **kwargs):
            if "token" in str(path):
                return io.StringIO("test-token-1234")
            raise OSError(f"unexpected open: {path}")

        with patch("socket.socket", return_value=mock_sock), \
             patch("builtins.open", side_effect=_fake_open):
            callback = build_callback(
                parser, inspector, engine,
                network_rules=network_rules,
                tracker=tracker,
            )
            # Step 1: SYN (Path A)
            syn_pkt = MockPacket(_make_tcp_syn(dst_ip=dst_ip, dst_port=HOSTNAME_PORT))
            callback(syn_pkt)
            assert syn_pkt.accepted, "SYN must be provisionally accepted"

            # Step 2: ClientHello (Path B)
            ch_pkt = MockPacket(_make_tcp_with_sni(sni, dst_ip=dst_ip, dst_port=HOSTNAME_PORT))
            callback(ch_pkt)

        import json
        parsed_payloads = [json.loads(p) for p in sent_payloads]
        return ch_pkt, parsed_payloads

    def test_matching_sni_produces_allow(self):
        ch_pkt, payloads = self._run_syn_then_client_hello(sni=ALLOWED_HOST)
        assert ch_pkt.accepted, "ClientHello with matching SNI must be accepted"
        assert not ch_pkt.dropped

    def test_matching_sni_emits_allow_event(self):
        _, payloads = self._run_syn_then_client_hello(sni=ALLOWED_HOST)
        # Only one event should have been sent (the Path B ALLOW; SYN sends nothing)
        assert len(payloads) == 1
        assert payloads[0]["verdict"]["decision"] == "ALLOW"

    def test_matching_sni_reason_is_provisional_allow(self):
        _, payloads = self._run_syn_then_client_hello(sni=ALLOWED_HOST)
        assert payloads[0]["verdict"]["reason"] == REASON_PROVISIONAL_ALLOW_SNI

    def test_non_matching_sni_produces_block(self):
        ch_pkt, payloads = self._run_syn_then_client_hello(sni=BLOCKED_HOST)
        assert ch_pkt.dropped, "ClientHello with non-matching SNI must be dropped"
        assert not ch_pkt.accepted

    def test_non_matching_sni_emits_block_event(self):
        _, payloads = self._run_syn_then_client_hello(sni=BLOCKED_HOST)
        assert len(payloads) == 1
        assert payloads[0]["verdict"]["decision"] == "BLOCK"

    def test_non_matching_sni_reason_is_provisional_block_sni(self):
        _, payloads = self._run_syn_then_client_hello(sni=BLOCKED_HOST)
        assert payloads[0]["verdict"]["reason"] == REASON_PROVISIONAL_BLOCK_SNI

    def test_tracker_entry_is_consumed_after_path_b(self):
        """After Path B resolves the entry, the tracker is empty."""
        parser, inspector, engine, network_rules = _make_components()
        tracker = PendingConnectionTracker()

        import io
        def _fake_open(path, *args, **kwargs):
            if "token" in str(path):
                return io.StringIO("test-token-1234")
            raise OSError(f"unexpected open: {path}")

        with patch("socket.socket"), \
             patch("builtins.open", side_effect=_fake_open):
            callback = build_callback(
                parser, inspector, engine,
                network_rules=network_rules,
                tracker=tracker,
            )
            callback(MockPacket(_make_tcp_syn(dst_port=HOSTNAME_PORT)))
            assert len(tracker) == 1
            callback(MockPacket(_make_tcp_with_sni(ALLOWED_HOST, dst_port=HOSTNAME_PORT)))
            assert len(tracker) == 0, "Entry must be consumed (popped) by Path B"

    def test_path_b_reason_strings_are_distinct(self):
        """ALLOW and BLOCK reason strings must not be equal."""
        assert REASON_PROVISIONAL_ALLOW_SNI != REASON_PROVISIONAL_BLOCK_SNI
        assert REASON_PROVISIONAL_BLOCK_SNI != REASON_PROVISIONAL_BLOCK_TTL


class TestSweep:
    """
    SWEEP: expired tracker entries produce BLOCK log events with the distinct
    TTL-expiry reason string. No packet drop is needed (no packet in hand).
    """

    def test_expired_entry_produces_block_event_with_ttl_reason(self):
        """An expired entry swept on the next packet produces the TTL-expiry BLOCK event."""
        parser, inspector, engine, network_rules = _make_components()
        tracker = PendingConnectionTracker()
        sent_payloads: List[bytes] = []

        mock_sock = MagicMock()
        mock_sock.__enter__ = lambda s: mock_sock
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_sock.sendto = lambda data, addr: sent_payloads.append(data)

        import io
        def _fake_open(path, *args, **kwargs):
            if "token" in str(path):
                return io.StringIO("test-token-sweep")
            raise OSError(f"unexpected open: {path}")

        with patch("socket.socket", return_value=mock_sock), \
             patch("builtins.open", side_effect=_fake_open):
            callback = build_callback(
                parser, inspector, engine,
                network_rules=network_rules,
                tracker=tracker,
            )

            # Step 1: SYN tracked normally
            syn_pkt = MockPacket(_make_tcp_syn(dst_port=HOSTNAME_PORT))
            callback(syn_pkt)
            assert len(tracker) == 1

            # Step 2: Manually expire the entry by reaching inside the tracker
            conn_key = list(tracker._pending.keys())[0]
            tracker._pending[conn_key].expires_at = time.time() - 1.0  # already expired

            # Step 3: Send an unrelated packet — the sweep fires before parsing
            # Use a packet that takes the stateless path (IP-only port, no hostname rules)
            unrelated_pkt = MockPacket(_make_tcp_ip_only(dst_ip=ALLOWED_IP, dst_port=IP_ONLY_PORT))
            callback(unrelated_pkt)

        import json
        parsed_payloads = [json.loads(p) for p in sent_payloads]
        # There must be exactly one event: the TTL-expiry BLOCK (plus possibly the
        # stateless ALLOW for the unrelated packet — filter to find the expiry one)
        expiry_events = [
            p for p in parsed_payloads
            if p["verdict"]["reason"] == REASON_PROVISIONAL_BLOCK_TTL
        ]
        assert len(expiry_events) == 1, (
            f"Expected exactly one TTL-expiry BLOCK event; got {len(expiry_events)}. "
            f"All events: {[p['verdict']['reason'] for p in parsed_payloads]}"
        )

    def test_expired_entry_produces_block_decision(self):
        """The TTL-expiry event carries decision=BLOCK."""
        parser, inspector, engine, network_rules = _make_components()
        tracker = PendingConnectionTracker()
        sent_payloads: List[bytes] = []

        mock_sock = MagicMock()
        mock_sock.__enter__ = lambda s: mock_sock
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_sock.sendto = lambda data, addr: sent_payloads.append(data)

        import io
        def _fake_open(path, *args, **kwargs):
            if "token" in str(path):
                return io.StringIO("test-token-sweep2")
            raise OSError(f"unexpected open: {path}")

        with patch("socket.socket", return_value=mock_sock), \
             patch("builtins.open", side_effect=_fake_open):
            callback = build_callback(
                parser, inspector, engine,
                network_rules=network_rules,
                tracker=tracker,
            )
            callback(MockPacket(_make_tcp_syn(dst_port=HOSTNAME_PORT)))
            conn_key = list(tracker._pending.keys())[0]
            tracker._pending[conn_key].expires_at = time.time() - 1.0

            callback(MockPacket(_make_tcp_ip_only(dst_ip=ALLOWED_IP, dst_port=IP_ONLY_PORT)))

        import json
        parsed_payloads = [json.loads(p) for p in sent_payloads]
        expiry_events = [
            p for p in parsed_payloads
            if p["verdict"]["reason"] == REASON_PROVISIONAL_BLOCK_TTL
        ]
        assert expiry_events[0]["verdict"]["decision"] == "BLOCK"

    def test_unexpired_entry_is_not_swept(self):
        """An entry that has not yet expired is left in the tracker after a sweep."""
        parser, inspector, engine, network_rules = _make_components()
        tracker = PendingConnectionTracker()
        sent_payloads: List[bytes] = []

        mock_sock = MagicMock()
        mock_sock.__enter__ = lambda s: mock_sock
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_sock.sendto = lambda data, addr: sent_payloads.append(data)

        import io
        def _fake_open(path, *args, **kwargs):
            if "token" in str(path):
                return io.StringIO("test-token-noexpiry")
            raise OSError(f"unexpected open: {path}")

        with patch("socket.socket", return_value=mock_sock), \
             patch("builtins.open", side_effect=_fake_open):
            callback = build_callback(
                parser, inspector, engine,
                network_rules=network_rules,
                tracker=tracker,
            )
            # SYN — tracked with full TTL
            callback(MockPacket(_make_tcp_syn(dst_port=HOSTNAME_PORT)))
            assert len(tracker) == 1

            # Another packet — sweep should NOT remove the still-fresh entry
            callback(MockPacket(_make_tcp_ip_only(dst_ip=ALLOWED_IP, dst_port=IP_ONLY_PORT)))

        import json
        parsed_payloads = [json.loads(p) for p in sent_payloads]
        expiry_events = [
            p for p in parsed_payloads
            if p["verdict"]["reason"] == REASON_PROVISIONAL_BLOCK_TTL
        ]
        assert expiry_events == [], "Unexpired entry must not produce a TTL-expiry event"
        assert len(tracker) == 1, "Unexpired entry must still be in the tracker"


class TestStatelessPath:
    """
    STATELESS: traffic to pure-IP-ruled ports continues through the existing
    stateless evaluation unchanged — Phase 2.5 must not alter this behaviour.
    """

    def test_allowed_ip_is_accepted(self):
        """A packet to an explicitly allowlisted IP is accepted statelessly."""
        parser, inspector, engine, network_rules = _make_components()
        tracker = PendingConnectionTracker()

        import io
        def _fake_open(path, *args, **kwargs):
            if "token" in str(path):
                return io.StringIO("test-token-stateless")
            raise OSError(f"unexpected open: {path}")

        with patch("socket.socket"), \
             patch("builtins.open", side_effect=_fake_open):
            callback = build_callback(
                parser, inspector, engine,
                network_rules=network_rules,
                tracker=tracker,
            )
            pkt = MockPacket(_make_tcp_ip_only(dst_ip=ALLOWED_IP, dst_port=IP_ONLY_PORT))
            callback(pkt)

        assert pkt.accepted, "Packet to allowlisted IP must be accepted via stateless path"
        assert not pkt.dropped

    def test_blocked_ip_is_dropped_statelessly(self):
        """A packet to a non-allowlisted IP is dropped statelessly."""
        parser, inspector, engine, network_rules = _make_components()
        tracker = PendingConnectionTracker()

        import io
        def _fake_open(path, *args, **kwargs):
            if "token" in str(path):
                return io.StringIO("test-token-block")
            raise OSError(f"unexpected open: {path}")

        with patch("socket.socket"), \
             patch("builtins.open", side_effect=_fake_open):
            callback = build_callback(
                parser, inspector, engine,
                network_rules=network_rules,
                tracker=tracker,
            )
            pkt = MockPacket(_make_tcp_ip_only(dst_ip="8.8.8.8", dst_port=IP_ONLY_PORT))
            callback(pkt)

        assert pkt.dropped, "Packet to non-allowlisted IP must be dropped via stateless path"

    def test_ip_traffic_does_not_enter_tracker(self):
        """SYN to an IP-only port must not be tracked."""
        parser, inspector, engine, network_rules = _make_components()
        tracker = PendingConnectionTracker()

        import io
        def _fake_open(path, *args, **kwargs):
            if "token" in str(path):
                return io.StringIO("test-token-notrack")
            raise OSError(f"unexpected open: {path}")

        with patch("socket.socket"), \
             patch("builtins.open", side_effect=_fake_open):
            callback = build_callback(
                parser, inspector, engine,
                network_rules=network_rules,
                tracker=tracker,
            )
            callback(MockPacket(_make_tcp_ip_only()))

        assert len(tracker) == 0


# ---------------------------------------------------------------------------
# TestConcurrentConnections (requires real 4-tuple — old placeholder failed this)
# ---------------------------------------------------------------------------

def _make_tcp_syn_with_sport(sport: int, dst_ip: str = "93.184.216.34", dst_port: int = 443) -> bytes:
    """Bare TCP SYN with a specific source port — for concurrent-connection tests."""
    from scapy.all import IP, TCP
    pkt = IP(src=JAIL_SRC_IP, dst=dst_ip) / TCP(sport=sport, dport=dst_port, flags="S")
    return bytes(pkt)


def _make_tcp_with_sni_and_sport(sni: str, sport: int, dst_ip: str = "93.184.216.34", dst_port: int = 443) -> bytes:
    """TCP ClientHello with a specific source port — for concurrent-connection tests."""
    from scapy.all import IP, TCP, Raw
    payload = _make_tls_client_hello(sni)
    pkt = IP(src=JAIL_SRC_IP, dst=dst_ip) / TCP(sport=sport, dport=dst_port) / Raw(load=payload)
    return bytes(pkt)


class TestConcurrentConnections:
    """
    Prove that two simultaneous connections to the same dst_ip:dst_port but
    from different ephemeral src_ports are tracked and resolved independently.

    WHY this test class: this is the exact collision case the old placeholder
    conn_key (dst_ip, dst_port, dst_ip, dst_port) could NOT handle — both
    connections would overwrite the same key. The real 4-tuple includes src_port
    and correctly distinguishes them.
    """

    def _build_callback_with_tracker(self, tracker: PendingConnectionTracker, token: str = "test-token-concurrent"):
        parser, inspector, engine, network_rules = _make_components()
        import io
        def _fake_open(path, *args, **kwargs):
            if "token" in str(path):
                return io.StringIO(token)
            raise OSError(f"unexpected open: {path}")
        return build_callback(parser, inspector, engine,
                              network_rules=network_rules, tracker=tracker), _fake_open

    def test_two_syns_create_two_tracker_entries(self):
        """Two SYNs from different src_ports to the same dst each create a separate entry."""
        tracker = PendingConnectionTracker()
        callback, _fake_open = self._build_callback_with_tracker(tracker)

        with patch("socket.socket"), patch("builtins.open", side_effect=_fake_open):
            callback(MockPacket(_make_tcp_syn_with_sport(sport=60001, dst_port=HOSTNAME_PORT)))
            callback(MockPacket(_make_tcp_syn_with_sport(sport=60002, dst_port=HOSTNAME_PORT)))

        assert len(tracker) == 2, (
            f"Expected 2 separate tracker entries for 2 different src_ports; got {len(tracker)}. "
            "Old placeholder conn_key would have overwritten the first entry."
        )

    def test_two_syns_both_accepted(self):
        """Both SYNs must be provisionally accepted."""
        tracker = PendingConnectionTracker()
        callback, _fake_open = self._build_callback_with_tracker(tracker)

        with patch("socket.socket"), patch("builtins.open", side_effect=_fake_open):
            syn_a = MockPacket(_make_tcp_syn_with_sport(sport=60001, dst_port=HOSTNAME_PORT))
            syn_b = MockPacket(_make_tcp_syn_with_sport(sport=60002, dst_port=HOSTNAME_PORT))
            callback(syn_a)
            callback(syn_b)

        assert syn_a.accepted and syn_b.accepted

    def test_resolving_one_does_not_affect_the_other(self):
        """
        Resolving connection A's ClientHello leaves connection B still tracked.
        The old placeholder would have caused both to share one key.
        """
        tracker = PendingConnectionTracker()
        sent_payloads: List[bytes] = []

        mock_sock = MagicMock()
        mock_sock.__enter__ = lambda s: mock_sock
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_sock.sendto = lambda data, addr: sent_payloads.append(data)

        callback, _fake_open = self._build_callback_with_tracker(tracker, "tok-resolve")

        with patch("socket.socket", return_value=mock_sock), \
             patch("builtins.open", side_effect=_fake_open):
            callback(MockPacket(_make_tcp_syn_with_sport(sport=60001, dst_port=HOSTNAME_PORT)))
            callback(MockPacket(_make_tcp_syn_with_sport(sport=60002, dst_port=HOSTNAME_PORT)))
            assert len(tracker) == 2

            callback(MockPacket(_make_tcp_with_sni_and_sport(
                ALLOWED_HOST, sport=60001, dst_port=HOSTNAME_PORT,
            )))

        assert len(tracker) == 1, (
            f"After resolving connection A, tracker should have 1 entry (B). Got {len(tracker)}."
        )

    def test_each_connection_resolved_independently(self):
        """
        Resolve A then B in sequence — each produces its own ALLOW event.
        If they shared a conn_key the second ClientHello would find nothing to resolve.
        """
        import json

        tracker = PendingConnectionTracker()
        sent_payloads: List[bytes] = []

        mock_sock = MagicMock()
        mock_sock.__enter__ = lambda s: mock_sock
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_sock.sendto = lambda data, addr: sent_payloads.append(data)

        callback, _fake_open = self._build_callback_with_tracker(tracker, "tok-seq")

        with patch("socket.socket", return_value=mock_sock), \
             patch("builtins.open", side_effect=_fake_open):
            callback(MockPacket(_make_tcp_syn_with_sport(sport=60001, dst_port=HOSTNAME_PORT)))
            callback(MockPacket(_make_tcp_syn_with_sport(sport=60002, dst_port=HOSTNAME_PORT)))

            callback(MockPacket(_make_tcp_with_sni_and_sport(
                ALLOWED_HOST, sport=60001, dst_port=HOSTNAME_PORT,
            )))
            callback(MockPacket(_make_tcp_with_sni_and_sport(
                ALLOWED_HOST, sport=60002, dst_port=HOSTNAME_PORT,
            )))

        allow_events = [
            json.loads(p) for p in sent_payloads
            if json.loads(p)["verdict"]["reason"] == REASON_PROVISIONAL_ALLOW_SNI
        ]
        assert len(allow_events) == 2, (
            f"Expected 2 independent ALLOW events; got {len(allow_events)}. "
            "Old placeholder conn_key would have left the second ClientHello unresolved."
        )
        assert len(tracker) == 0
