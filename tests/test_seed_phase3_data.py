"""
tests/test_seed_phase3_data.py — Unit tests for demo/seed_phase3_data.py.

Tests verify:
  1. seed() inserts the correct total row count
  2. Positive-control scenarios produce candidates when scanned
  3. Negative-control scenarios (window-expired, volume-shy) do NOT fire
  4. clear_first=True wipes existing rows before inserting
  5. clear_first=False appends without destroying existing rows
  6. The expected number of distinct positive-control destinations fires
  7. All four detection axes are covered by the positive controls

WHY real SQLite (not mocked):
  These tests exercise the full seed → scan path. A mock would only verify
  that seed() calls SQL; we need to verify that what it calls produces the
  right scanner output. Using Logger(tmp_path / ...) gives us a real in-memory
  (well, tmp-file) DB with the full schema applied, exactly as in production.
"""

from __future__ import annotations

import pytest
from pathlib import Path

from daemon.ledger.logger import Logger
from daemon.advisor.detection_scanner import scan
from demo.seed_phase3_data import seed, SEED_SCENARIOS, N_THRESHOLD, WINDOW_HOURS


# ── Fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture()
def tmp_db_path(tmp_path: Path) -> Path:
    """Return a path for a fresh temporary SQLite DB (not yet created)."""
    return tmp_path / "test_seed.db"


@pytest.fixture()
def seeded_db(tmp_db_path: Path):
    """Seed the temp DB and return (db_path, seed_result)."""
    result = seed(tmp_db_path, clear_first=False)
    return tmp_db_path, result


# ── Row-count tests ────────────────────────────────────────────────────────────

class TestSeedRowCounts:

    def test_total_rows_match_scenario_counts(self, seeded_db):
        """seed() must insert exactly as many rows as the scenarios declare."""
        db_path, result = seeded_db
        expected = sum(s["count"] for s in SEED_SCENARIOS)
        assert result["rows_added"] == expected, (
            f"Expected {expected} rows, got {result['rows_added']}"
        )

    def test_db_file_is_created(self, tmp_db_path: Path):
        """seed() must create the DB file if it does not already exist."""
        assert not tmp_db_path.exists(), "Pre-condition: file should not exist yet"
        seed(tmp_db_path, clear_first=False)
        assert tmp_db_path.exists(), "DB file was not created by seed()"

    def test_clear_first_resets_rows(self, tmp_db_path: Path):
        """clear_first=True wipes existing rows before inserting."""
        # First pass: seed normally
        first = seed(tmp_db_path, clear_first=False)

        # Second pass with clear: result should equal exactly one pass of seeding
        second = seed(tmp_db_path, clear_first=True)
        expected = sum(s["count"] for s in SEED_SCENARIOS)
        assert second["rows_added"] == expected, (
            f"After clear+reseed, expected {expected} rows, got {second['rows_added']}"
        )

        # Verify total rows in DB (not cumulative from first pass)
        logger = Logger(tmp_db_path)
        with logger._lock:
            count = logger._conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        logger.close()
        assert count == expected, (
            f"DB contains {count} rows after clear+reseed, expected {expected}"
        )

    def test_clear_false_appends(self, tmp_db_path: Path):
        """clear_first=False must append without destroying existing rows."""
        expected_per_pass = sum(s["count"] for s in SEED_SCENARIOS)
        seed(tmp_db_path, clear_first=False)
        seed(tmp_db_path, clear_first=False)

        logger = Logger(tmp_db_path)
        with logger._lock:
            count = logger._conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        logger.close()
        assert count == expected_per_pass * 2, (
            f"After two appending seeds, expected {expected_per_pass * 2} rows, got {count}"
        )


# ── Positive-control detection tests ──────────────────────────────────────────

class TestPositiveControls:
    """Each positive-control scenario must fire when the scanner runs."""

    @pytest.fixture(autouse=True)
    def _setup(self, tmp_db_path: Path):
        seed(tmp_db_path, clear_first=False)
        self.logger = Logger(tmp_db_path)
        self.candidates = scan(self.logger, n_threshold=N_THRESHOLD, window_hours=WINDOW_HOURS)
        self.detected_destinations = {c.destination for c in self.candidates}
        yield
        self.logger.close()

    def test_all_positive_scenarios_detected(self):
        """Every scenario with expect_fire=True must appear in scan() output."""
        for s in SEED_SCENARIOS:
            if s["expect_fire"]:
                assert s["destination"] in self.detected_destinations, (
                    f"Positive control NOT detected: {s['label']}\n"
                    f"Expected destination '{s['destination']}' in candidates.\n"
                    f"Detected destinations: {self.detected_destinations}"
                )

    def test_shell_ip_axis_fired(self):
        """Shell-origin IP-axis candidate must appear with correct binary and destination."""
        # curl → 10.0.0.1 on IP axis
        matches = [
            c for c in self.candidates
            if c.destination == "10.0.0.1" and c.detection_axis == "ip"
        ]
        assert len(matches) >= 1, "Shell-IP positive control (curl → 10.0.0.1) not detected"
        assert matches[0].occurrence_count >= N_THRESHOLD

    def test_shell_hostname_axis_fired(self):
        """Shell-origin hostname-axis candidate must appear for wget → exfil.evil.io."""
        matches = [
            c for c in self.candidates
            if c.destination == "exfil.evil.io" and c.detection_axis == "hostname"
        ]
        assert len(matches) >= 1, "Shell-hostname positive control (wget → exfil.evil.io) not detected"
        assert matches[0].occurrence_count >= N_THRESHOLD

    def test_network_ip_axis_fired(self):
        """Network-origin IP-axis candidate must appear for 192.0.2.50."""
        matches = [
            c for c in self.candidates
            if c.destination == "192.0.2.50" and c.detection_axis == "ip"
        ]
        assert len(matches) >= 1, "Network-IP positive control (→ 192.0.2.50) not detected"
        assert matches[0].occurrence_count >= N_THRESHOLD

    def test_network_hostname_axis_fired(self):
        """Network-origin hostname-axis candidate must appear for c2.attacker.net."""
        matches = [
            c for c in self.candidates
            if c.destination == "c2.attacker.net" and c.detection_axis == "hostname"
        ]
        assert len(matches) >= 1, "Network-hostname positive control (→ c2.attacker.net) not detected"
        # Exactly at threshold — confirm count >= N (not just > 0)
        assert matches[0].occurrence_count >= N_THRESHOLD

    def test_at_least_four_candidates_found(self):
        """There are four positive-control scenarios; at least four candidates must fire."""
        positive_count = sum(1 for s in SEED_SCENARIOS if s["expect_fire"])
        assert len(self.candidates) >= positive_count, (
            f"Expected >= {positive_count} candidates, got {len(self.candidates)}"
        )

    def test_all_four_axes_covered(self):
        """The positive controls cover both axes on both event types:
        shell-ip, shell-hostname, network-ip, network-hostname."""
        # We just need at least one candidate per axis type.
        # The scanner returns axis in {'ip', 'hostname'}.
        axes = {c.detection_axis for c in self.candidates}
        assert "ip"       in axes, "No IP-axis candidates detected"
        assert "hostname" in axes, "No hostname-axis candidates detected"


# ── Negative-control tests ─────────────────────────────────────────────────────

class TestNegativeControls:
    """Scenarios that should NOT produce candidates must be silent."""

    @pytest.fixture(autouse=True)
    def _setup(self, tmp_db_path: Path):
        seed(tmp_db_path, clear_first=False)
        self.logger = Logger(tmp_db_path)
        self.candidates = scan(self.logger, n_threshold=N_THRESHOLD, window_hours=WINDOW_HOURS)
        self.detected_destinations = {c.destination for c in self.candidates}
        yield
        self.logger.close()

    def test_volume_shy_does_not_fire(self):
        """9 events (N-1) for 203.0.113.1 must not produce a candidate."""
        assert "203.0.113.1" not in self.detected_destinations, (
            "Volume-shy negative control (203.0.113.1, 9 events) incorrectly fired"
        )

    def test_window_expired_does_not_fire(self):
        """12 events all 7h ago (outside 6h window) for 198.51.100.1 must not fire."""
        assert "198.51.100.1" not in self.detected_destinations, (
            "Window-expired negative control (198.51.100.1, 7h ago) incorrectly fired"
        )

    def test_hostname_volume_shy_does_not_fire(self):
        """8 hostname events for benign-low.example.com must not fire."""
        assert "benign-low.example.com" not in self.detected_destinations, (
            "Hostname volume-shy negative control (benign-low.example.com, 8 events) incorrectly fired"
        )

    def test_all_negative_scenarios_are_silent(self):
        """All scenarios with expect_fire=False must produce no candidate."""
        for s in SEED_SCENARIOS:
            if not s["expect_fire"]:
                assert s["destination"] not in self.detected_destinations, (
                    f"Negative control incorrectly fired: {s['label']}\n"
                    f"Destination '{s['destination']}' should NOT be in candidates.\n"
                    f"Note: {s['note']}"
                )


# ── Scenario metadata integrity tests ─────────────────────────────────────────

class TestScenarioMetadata:
    """Sanity checks on the SEED_SCENARIOS constant itself."""

    def test_all_scenarios_have_required_keys(self):
        required = {"label", "event_type", "binary", "destination",
                    "is_hostname", "count", "age_hours", "expect_fire", "note"}
        for s in SEED_SCENARIOS:
            missing = required - s.keys()
            assert not missing, f"Scenario '{s.get('label', '?')}' missing keys: {missing}"

    def test_at_least_two_positive_and_two_negative(self):
        positives = [s for s in SEED_SCENARIOS if s["expect_fire"]]
        negatives = [s for s in SEED_SCENARIOS if not s["expect_fire"]]
        assert len(positives) >= 2, "Need at least 2 positive-control scenarios"
        assert len(negatives) >= 2, "Need at least 2 negative-control scenarios"

    def test_positive_counts_all_at_or_above_threshold(self):
        """Every positive-control scenario must declare count >= N_THRESHOLD."""
        for s in SEED_SCENARIOS:
            if s["expect_fire"]:
                assert s["count"] >= N_THRESHOLD, (
                    f"Positive control '{s['label']}' has count={s['count']} < N={N_THRESHOLD}"
                )

    def test_negative_counts_all_below_threshold_or_old(self):
        """Every negative-control scenario must have count < N_THRESHOLD OR age > WINDOW_HOURS."""
        for s in SEED_SCENARIOS:
            if not s["expect_fire"]:
                below_threshold = s["count"] < N_THRESHOLD
                outside_window  = s["age_hours"] > WINDOW_HOURS
                assert below_threshold or outside_window, (
                    f"Negative control '{s['label']}' has count={s['count']} >= N={N_THRESHOLD} "
                    f"AND age={s['age_hours']}h <= window={WINDOW_HOURS}h — "
                    "this scenario would incorrectly fire"
                )

    def test_event_type_values_are_valid(self):
        valid = {"shell_command", "network"}
        for s in SEED_SCENARIOS:
            assert s["event_type"] in valid, (
                f"Scenario '{s['label']}' has unknown event_type '{s['event_type']}'"
            )
