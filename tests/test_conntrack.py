"""
tests/test_conntrack.py — Unit tests for sidecar/conntrack.py.

Phase 2.5 component. These tests verify the PendingConnectionTracker state
primitive in complete isolation — no Docker, no NFQUEUE, no Scapy, no daemon
imports. Every test is deterministic (time is passed in explicitly, not
mocked via monkeypatching).
"""

import pytest

from sidecar.conntrack import PendingConnectionTracker, PendingEntry, DEFAULT_TTL_SECONDS


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------

# A fixed "now" used as the base timestamp across tests.
T0: float = 1_000_000.0

def make_key(src_ip="10.0.0.1", src_port=54321, dst_ip="93.184.216.34", dst_port=443):
    """Return a canonical 4-tuple conn_key."""
    return (src_ip, src_port, dst_ip, dst_port)


# ---------------------------------------------------------------------------
# TestTrackAndResolve
# ---------------------------------------------------------------------------

class TestTrackAndResolve:
    """Basic track/resolve round-trip behaviour."""

    def test_track_then_resolve_returns_entry(self):
        """track() followed by resolve() returns the PendingEntry."""
        tracker = PendingConnectionTracker()
        key = make_key()
        tracker.track(key, dst_port=443, expires_at=T0 + 10.0)

        entry = tracker.resolve(key)

        assert entry is not None
        assert isinstance(entry, PendingEntry)
        assert entry.conn_key == key
        assert entry.dst_port == 443
        assert entry.expires_at == T0 + 10.0

    def test_resolve_on_untracked_key_returns_none(self):
        """resolve() on a key that was never tracked returns None."""
        tracker = PendingConnectionTracker()
        result = tracker.resolve(make_key())
        assert result is None

    def test_resolve_removes_entry_from_tracker(self):
        """After resolve(), is_pending() returns False for that key."""
        tracker = PendingConnectionTracker()
        key = make_key()
        tracker.track(key, dst_port=443, expires_at=T0 + 10.0)
        tracker.resolve(key)

        assert not tracker.is_pending(key)

    def test_resolve_can_only_be_called_once_per_key(self):
        """A second resolve() on the same key returns None (entry was popped)."""
        tracker = PendingConnectionTracker()
        key = make_key()
        tracker.track(key, dst_port=443, expires_at=T0 + 10.0)

        first = tracker.resolve(key)
        second = tracker.resolve(key)

        assert first is not None
        assert second is None

    def test_track_second_time_overwrites_entry(self):
        """Tracking an already-tracked key silently overwrites it (SYN retransmit case)."""
        tracker = PendingConnectionTracker()
        key = make_key()
        tracker.track(key, dst_port=443, expires_at=T0 + 5.0)
        tracker.track(key, dst_port=443, expires_at=T0 + 15.0)  # retransmit resets TTL

        entry = tracker.resolve(key)
        assert entry is not None
        assert entry.expires_at == T0 + 15.0  # second track's TTL wins


# ---------------------------------------------------------------------------
# TestIsPending
# ---------------------------------------------------------------------------

class TestIsPending:
    """is_pending() reflects tracker state correctly at every stage."""

    def test_is_pending_false_before_track(self):
        tracker = PendingConnectionTracker()
        assert not tracker.is_pending(make_key())

    def test_is_pending_true_after_track(self):
        tracker = PendingConnectionTracker()
        key = make_key()
        tracker.track(key, dst_port=443, expires_at=T0 + 10.0)
        assert tracker.is_pending(key)

    def test_is_pending_false_after_resolve(self):
        tracker = PendingConnectionTracker()
        key = make_key()
        tracker.track(key, dst_port=443, expires_at=T0 + 10.0)
        tracker.resolve(key)
        assert not tracker.is_pending(key)

    def test_is_pending_false_after_sweep_removes_entry(self):
        tracker = PendingConnectionTracker()
        key = make_key()
        tracker.track(key, dst_port=443, expires_at=T0 + 10.0)
        # Sweep at T0+10 — boundary is <=, so this entry expires exactly now.
        tracker.sweep_expired(now=T0 + 10.0)
        assert not tracker.is_pending(key)

    def test_is_pending_independent_across_keys(self):
        """is_pending() for one key is not affected by tracking another key."""
        tracker = PendingConnectionTracker()
        key_a = make_key(src_port=1111)
        key_b = make_key(src_port=2222)
        tracker.track(key_a, dst_port=443, expires_at=T0 + 10.0)

        assert tracker.is_pending(key_a)
        assert not tracker.is_pending(key_b)


# ---------------------------------------------------------------------------
# TestSweepExpired
# ---------------------------------------------------------------------------

class TestSweepExpired:
    """sweep_expired() removes entries at/past their TTL and leaves others."""

    def test_sweep_removes_expired_entries(self):
        """Entries with expires_at <= now are removed and returned."""
        tracker = PendingConnectionTracker()
        expired_key = make_key(src_port=1001)
        tracker.track(expired_key, dst_port=443, expires_at=T0 + 5.0)

        removed = tracker.sweep_expired(now=T0 + 10.0)

        assert len(removed) == 1
        assert removed[0].conn_key == expired_key
        assert not tracker.is_pending(expired_key)

    def test_sweep_leaves_unexpired_entries(self):
        """Entries with expires_at > now are not touched."""
        tracker = PendingConnectionTracker()
        fresh_key = make_key(src_port=2002)
        tracker.track(fresh_key, dst_port=443, expires_at=T0 + 20.0)

        removed = tracker.sweep_expired(now=T0 + 10.0)

        assert removed == []
        assert tracker.is_pending(fresh_key)

    def test_sweep_removes_only_expired_leaves_others(self):
        """With mixed entries, only the expired ones are removed."""
        tracker = PendingConnectionTracker()
        expired_key = make_key(src_port=3001)
        fresh_key   = make_key(src_port=3002)

        tracker.track(expired_key, dst_port=443, expires_at=T0 + 5.0)
        tracker.track(fresh_key,   dst_port=443, expires_at=T0 + 15.0)

        removed = tracker.sweep_expired(now=T0 + 10.0)

        assert len(removed) == 1
        assert removed[0].conn_key == expired_key
        assert not tracker.is_pending(expired_key)
        assert tracker.is_pending(fresh_key)

    def test_sweep_boundary_at_exactly_expires_at_removes_entry(self):
        """expires_at == now is treated as expired (boundary is inclusive)."""
        tracker = PendingConnectionTracker()
        key = make_key(src_port=4001)
        tracker.track(key, dst_port=443, expires_at=T0 + 10.0)

        removed = tracker.sweep_expired(now=T0 + 10.0)

        assert len(removed) == 1
        assert removed[0].conn_key == key

    def test_sweep_one_second_before_expiry_leaves_entry(self):
        """expires_at == now + 1 is not yet expired."""
        tracker = PendingConnectionTracker()
        key = make_key(src_port=5001)
        tracker.track(key, dst_port=443, expires_at=T0 + 11.0)

        removed = tracker.sweep_expired(now=T0 + 10.0)

        assert removed == []
        assert tracker.is_pending(key)

    def test_sweep_on_empty_tracker_returns_empty_list(self):
        """sweep_expired() on an empty tracker returns [] without error."""
        tracker = PendingConnectionTracker()
        removed = tracker.sweep_expired(now=T0 + 99.0)
        assert removed == []

    def test_sweep_multiple_expired_all_returned(self):
        """Multiple expired entries are all returned by a single sweep."""
        tracker = PendingConnectionTracker()
        keys = [make_key(src_port=6000 + i) for i in range(5)]
        for key in keys:
            tracker.track(key, dst_port=443, expires_at=T0 + 3.0)

        removed = tracker.sweep_expired(now=T0 + 10.0)

        assert len(removed) == 5
        assert len(tracker) == 0


# ---------------------------------------------------------------------------
# TestLen
# ---------------------------------------------------------------------------

class TestLen:
    """__len__ accurately reflects the number of tracked connections."""

    def test_empty_tracker_has_len_zero(self):
        assert len(PendingConnectionTracker()) == 0

    def test_len_increases_with_track(self):
        tracker = PendingConnectionTracker()
        for i in range(3):
            tracker.track(make_key(src_port=7000 + i), dst_port=443, expires_at=T0 + 10.0)
        assert len(tracker) == 3

    def test_len_decreases_after_resolve(self):
        tracker = PendingConnectionTracker()
        key = make_key()
        tracker.track(key, dst_port=443, expires_at=T0 + 10.0)
        tracker.resolve(key)
        assert len(tracker) == 0

    def test_len_decreases_after_sweep(self):
        tracker = PendingConnectionTracker()
        tracker.track(make_key(src_port=8001), dst_port=443, expires_at=T0 + 5.0)
        tracker.track(make_key(src_port=8002), dst_port=443, expires_at=T0 + 5.0)
        tracker.sweep_expired(now=T0 + 10.0)
        assert len(tracker) == 0


# ---------------------------------------------------------------------------
# TestDefaultTTL
# ---------------------------------------------------------------------------

class TestDefaultTTL:
    """Verify the DEFAULT_TTL_SECONDS constant is documented and reasonable."""

    def test_default_ttl_is_positive(self):
        assert DEFAULT_TTL_SECONDS > 0

    def test_default_ttl_is_at_most_60_seconds(self):
        """TTL must stay short — this is not a long-lived session store."""
        assert DEFAULT_TTL_SECONDS <= 60.0
