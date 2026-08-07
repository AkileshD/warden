"""
sidecar/conntrack.py — In-memory pending-connection tracker for Phase 2.5.

Phase 2.5 component. Exists because the stateless NFQUEUE callback in
interceptor.py evaluates every packet in isolation. A TCP SYN carries no
payload and therefore no SNI, so it always falls through to default-deny
before the TLS ClientHello (which carries the SNI) can be seen. This module
provides the state primitive that lets the sidecar remember a SYN long enough
to evaluate the SNI from the ClientHello that follows it.

CONTRACT: This class has zero dependency on Docker, NFQUEUE, Scapy, or any
  network I/O. It is a pure in-memory data structure. It must remain importable
  and fully testable without any container or kernel module present.

WHY sidecar/conntrack.py (not daemon/): this state is entirely local to one
  running sidecar process. It has no ledger interaction, no daemon IPC, and no
  policy awareness. The daemon never needs to see it. Keeping it in sidecar/
  preserves the sidecar/daemon boundary established by the existing layout.

WHY tuple conn_key (not a named class): a 4-tuple (src_ip, src_port, dst_ip,
  dst_port) is already hashable, self-documenting, and directly constructable
  from Scapy-parsed IP/TCP fields without an intermediate adapter. Introducing a
  wrapper class would add indirection without adding information.

WHY TTL=10s: the SYN-to-ClientHello gap on a local or low-latency connection is
  typically <100ms. 10 seconds is 100x that margin — enough to survive a slow
  TLS handshake or a brief burst of retransmits — while still expiring
  aggressively enough that a half-open connection (SYN with no follow-through)
  does not accumulate indefinitely. If real traffic shows this TTL is too tight,
  widen it; if memory pressure is a concern, tighten it. The constant is named
  and documented rather than magic so it is trivial to adjust.

RISK: this store is not thread-safe. NFQUEUE callbacks in netfilterqueue 1.x
  are dispatched on a single thread (nfqueue.run() is a blocking loop). If a
  future version introduces multi-threaded dispatch, add threading.Lock here.
  See TODO(phase2.5) below.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

# CONTRACT: conn_key is always a 4-tuple (src_ip, src_port, dst_ip, dst_port).
ConnKey = Tuple[str, int, str, int]

# WHY 10s: see module docstring. Adjust here and nowhere else.
DEFAULT_TTL_SECONDS: float = 10.0


@dataclass
class PendingEntry:
    """One provisionally-allowed connection waiting for SNI resolution."""
    conn_key: ConnKey
    dst_port: int
    expires_at: float  # unix timestamp


class PendingConnectionTracker:
    """
    Tracks TCP connections that have been provisionally allowed past the SYN
    stage but have not yet had their SNI evaluated.

    Lifecycle of a tracked connection:
      1. SYN arrives on a port with hostname-based ALLOW rules.
         interceptor.py calls track(conn_key, dst_port, expires_at).
      2. ClientHello arrives. interceptor.py calls resolve(conn_key) to pop
         the entry, extract the SNI, and make the real verdict.
      3. If no ClientHello arrives within TTL, sweep_expired() discards the
         entry on the next call (typically on the next packet).

    CONTRACT: all public methods are O(n) in the number of tracked connections
      at most. In practice n is tiny (SYN-to-ClientHello gap is milliseconds).
    """

    def __init__(self) -> None:
        # WHY dict keyed by ConnKey: O(1) lookup by 4-tuple is exactly what
        # resolve() and is_pending() need. We never need ordered iteration
        # except in sweep_expired(), where we scan all entries anyway.
        self._pending: Dict[ConnKey, PendingEntry] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def track(self, conn_key: ConnKey, dst_port: int, expires_at: float) -> None:
        """
        Record a provisional connection.

        Args:
            conn_key:   4-tuple (src_ip, src_port, dst_ip, dst_port).
            dst_port:   Destination port (redundant with conn_key[3], kept
                        explicit so the caller does not have to unpack).
            expires_at: Unix timestamp after which this entry is stale.
                        Callers should pass time.time() + DEFAULT_TTL_SECONDS.

        WHY overwrite silently on duplicate key: a SYN retransmit should reset
          the TTL rather than leaving the original (shorter-lived) entry. The
          retransmit carries identical fields, so overwriting is safe.
        """
        self._pending[conn_key] = PendingEntry(
            conn_key=conn_key,
            dst_port=dst_port,
            expires_at=expires_at,
        )

    def is_pending(self, conn_key: ConnKey) -> bool:
        """Return True if conn_key is currently being tracked."""
        return conn_key in self._pending

    def resolve(self, conn_key: ConnKey) -> Optional[PendingEntry]:
        """
        Remove and return the tracked entry for conn_key, or None if not found.

        WHY pop (not get): once the SNI is seen, the connection is no longer
          pending — it has been given a definitive verdict. Leaving it in the
          map would cause a second spurious lookup on the next packet of the
          same connection (e.g. the HTTP request). Pop terminates tracking.

        # TODO(phase2.5): decide whether subsequent packets in a resolved
          ALLOW connection should be tracked in a separate "established"
          table or simply passed through by the stateless inspector. The
          current design does neither — each subsequent packet is evaluated
          statelessly — which is correct for Phase 2.5's minimal scope
          (hostname-based ALLOW at handshake time) but may need revisiting
          if retroactive enforcement of an ALLOW is required beyond the SYN.
        """
        return self._pending.pop(conn_key, None)

    def sweep_expired(self, now: float) -> list[PendingEntry]:
        """
        Remove and return all entries whose expires_at <= now.

        Args:
            now: Current unix timestamp (passed in to allow deterministic
                 testing without mocking time.time()).

        Returns:
            List of expired PendingEntry objects (may be empty).

        WHY caller-supplied now: makes the sweep fully deterministic in tests.
          The caller in interceptor.py will pass time.time(); tests pass a
          fixed value.

        RISK: if the tracker grows unexpectedly (e.g. a SYN flood), this scan
          is O(n). For Phase 2.5 traffic volumes (a single agent's egress),
          this is fine. A production hardening pass could cap the tracker size
          or use a min-heap indexed by expires_at.
        """
        expired_keys = [
            key for key, entry in self._pending.items()
            if entry.expires_at <= now
        ]
        expired_entries = [self._pending.pop(key) for key in expired_keys]
        return expired_entries

    def __len__(self) -> int:
        """Return the number of currently-tracked connections."""
        return len(self._pending)
