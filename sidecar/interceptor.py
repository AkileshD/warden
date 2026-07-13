#!/usr/bin/env python3
"""
sidecar/interceptor.py — Warden Network Sidecar Interceptor

CONTRACT: This is the entry point for the warden-sidecar container.
          Full implementation is TODO(phase5). This stub:
            1. Verifies the ledger volume is mounted and writable.
            2. Verifies netfilterqueue is importable (proves the
               nfnetlink_queue kernel module is present and loaded).
            3. Stays alive so docker-compose does not mark the service
               as crashed, allowing the container setup to be validated
               before any NFQUEUE code is written.

WHY a stub rather than nothing:
    docker-compose up starts all services. If interceptor.py doesn't
    exist or exits immediately, Docker marks the sidecar as exited/failed.
    The stub lets us verify the full container environment — volume mounts,
    network namespace sharing, capability grants — before writing a single
    line of NFQUEUE/iptables code. Separate concerns: get the infrastructure
    right first, then add the interception logic on top of a known-good base.

STARTUP SEQUENCE (to be implemented in phase5):
    1. setup_iptables()
         Insert: iptables -I OUTPUT -j NFQUEUE --queue-num 0
         WHY OUTPUT (not FORWARD): because the sidecar shares the jail's
         network namespace (network_mode: "service:jail" in compose). From
         inside that shared namespace, the jail's outbound packets appear
         as OUTPUT packets — they originate from this namespace. FORWARD
         would apply to packets being routed through a namespace, not
         packets originating within it.
         Register atexit handler to remove the rule on clean exit.
    2. nfqueue.bind(queue_num=0, callback=packet_callback)
    3. nfqueue.run()  — blocks, calling packet_callback for each packet
    On KeyboardInterrupt or signal: teardown_iptables(), exit cleanly.

PER-PACKET CALLBACK (to be implemented in phase5):
    packet_callback(packet):
        raw = packet.get_payload()
        parsed = PacketParser.parse(raw)          # daemon/parser/packet_parser.py
        verdict = NetworkInspector.inspect(parsed) # daemon/inspectors/network_inspector.py
        final = RuleEngine.evaluate([verdict])     # daemon/rules/engine.py
        LedgerLogger.record(LedgerEvent(...))      # daemon/ledger/logger.py
        if final.decision == Decision.ALLOW:
            packet.accept()
        else:                                      # BLOCK or FLAG → drop
            packet.drop()
"""

import os
import sys
import time

# TODO(phase5): from daemon.parser.packet_parser import PacketParser
# TODO(phase5): from daemon.inspectors.network_inspector import NetworkInspector
# TODO(phase5): from daemon.rules.engine import RuleEngine
# TODO(phase5): from daemon.ledger.logger import LedgerLogger, LedgerEvent
# TODO(phase5): import netfilterqueue
# TODO(phase5): import subprocess (for iptables calls)

LEDGER_PATH = os.environ.get("WARDEN_LEDGER_PATH", "/data/ledger/warden.db")
NFQUEUE_NUM = 0


def verify_environment() -> bool:
    """
    Verify the container environment before attempting any NFQUEUE work.
    Returns True if all checks pass, False (and prints errors) otherwise.

    Checks:
      1. Ledger directory exists and is writable.
      2. netfilterqueue is importable (proves nfnetlink_queue kernel module
         is loaded — if the module is missing, this import raises OSError).
    """
    ok = True

    # Check 1: ledger volume mount
    ledger_dir = os.path.dirname(LEDGER_PATH)
    if not os.path.isdir(ledger_dir):
        print(
            f"[warden-sidecar] ERROR: ledger directory {ledger_dir!r} does not exist.\n"
            "  Is the warden_ledger volume mounted? Check docker-compose.yml volumes.",
            file=sys.stderr,
            flush=True,
        )
        ok = False
    else:
        # Try writing a canary file to confirm write permission.
        canary = os.path.join(ledger_dir, ".sidecar_write_check")
        try:
            with open(canary, "w") as f:
                f.write("ok")
            os.remove(canary)
            print(f"[warden-sidecar] ledger volume OK: {ledger_dir} (writable)", flush=True)
        except OSError as e:
            print(
                f"[warden-sidecar] ERROR: cannot write to ledger directory {ledger_dir!r}: {e}",
                file=sys.stderr,
                flush=True,
            )
            ok = False

    # Check 2: netfilterqueue importability
    # WHY: if the kernel module nfnetlink_queue is not loaded on the host,
    # netfilterqueue will import fine but nfqueue.bind() will raise OSError
    # at runtime. We can detect the module absence early by importing and
    # doing a quick sanity check here.
    try:
        import netfilterqueue  # type: ignore # noqa: F401
        print("[warden-sidecar] netfilterqueue import OK (nfnetlink_queue module present)", flush=True)
    except ImportError as e:
        print(
            f"[warden-sidecar] ERROR: cannot import netfilterqueue: {e}\n"
            "  Was it installed in the sidecar image? Try: docker-compose build warden-sidecar",
            file=sys.stderr,
            flush=True,
        )
        ok = False
    except OSError as e:
        print(
            f"[warden-sidecar] ERROR: netfilterqueue import raised OSError: {e}\n"
            "  The nfnetlink_queue kernel module may not be loaded on the host.\n"
            "  Verify: docker run --rm --cap-add=NET_ADMIN python:3.11-slim \\\n"
            "    python3 -c \"import netfilterqueue; print('OK')\"",
            file=sys.stderr,
            flush=True,
        )
        ok = False

    return ok


def main() -> None:
    print("[warden-sidecar] interceptor starting (stub — Phase 5 not yet implemented)", flush=True)
    print(f"[warden-sidecar] python: {sys.version}", flush=True)
    print(f"[warden-sidecar] ledger path: {LEDGER_PATH}", flush=True)
    print(f"[warden-sidecar] NFQUEUE queue number: {NFQUEUE_NUM}", flush=True)
    print(f"[warden-sidecar] PYTHONPATH: {os.environ.get('PYTHONPATH', '(not set)')}", flush=True)

    if not verify_environment():
        print("[warden-sidecar] environment checks FAILED — see errors above", file=sys.stderr, flush=True)
        sys.exit(1)

    print("[warden-sidecar] environment checks PASSED", flush=True)
    print(
        "[warden-sidecar] stub heartbeat loop running.\n"
        "  NFQUEUE interception is not active — implement in phase5.\n"
        "  This container is healthy; use it to verify compose networking and volumes.",
        flush=True,
    )

    # TODO(phase5): replace this loop with:
    #   setup_iptables(queue_num=NFQUEUE_NUM)
    #   nfqueue = netfilterqueue.NetfilterQueue()
    #   nfqueue.bind(NFQUEUE_NUM, packet_callback)
    #   try:
    #       nfqueue.run()
    #   except KeyboardInterrupt:
    #       pass
    #   finally:
    #       teardown_iptables(queue_num=NFQUEUE_NUM)

    while True:
        time.sleep(30)
        print("[warden-sidecar] heartbeat (stub — no packets being intercepted)", flush=True)


if __name__ == "__main__":
    main()
