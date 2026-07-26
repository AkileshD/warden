"""
tests/test_phase3_advisor.py — Phase 3 Smart Policy Loop test suite.

All tests use real in-memory SQLite databases via Logger (not mocks).
Synthetic rows are inserted via logger._conn.execute() directly for speed
and precision, matching exactly what the daemon would write in production.

Test coverage per the implementation plan:
  1. Detection scanner — threshold boundary (N-1, N, N+1)
  2. Detection scanner — window cutoff (event older than T hours excluded)
  3. Detection scanner — event_type filter (shell events not counted)
  4. Detection scanner — two distinct pairs produce two candidates
  5. Template engine — correct field population in reasoning_text
  6. Template engine — hostname vs dst_ip key selection in proposed YAML
  7. Template engine — proposed YAML parses as valid YAML
  8. Dry-run replay — correct A-of-B figures
  9. Dry-run replay — policy.yaml immutability (byte-for-byte after replay)
  10. Dry-run replay — empty ledger returns (0, 0)
  11. Logger proposed_rules — round-trip write/list
  12. Logger proposed_rules — list_pending_proposals excludes non-pending rows
  13. Logger proposed_rules — update_proposal_status transitions correctly
  14. Logger proposed_rules — update_proposal_status raises on invalid status
  15. Approval CLI — permissive_change gate (flag absent → refuses)
  16. Approval CLI — permissive_change gate (flag present → allowed)
"""

from __future__ import annotations

import json
import sqlite3
import tempfile
import time
from pathlib import Path

import pytest
import yaml

from daemon.ledger.logger import Logger, LedgerEvent, ProposedRule
from daemon.advisor.detection_scanner import scan, DetectionCandidate
from daemon.advisor.dry_run_replay import replay
from daemon.advisor.template_engine import (
    build_proposed_rule,
    build_reasoning_text,
    is_permissive,
    _is_hostname,
)
from daemon.advisor.approval_cli import check_approve_permissive_gate


# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture()
def tmp_db(tmp_path):
    """Return a Logger backed by a temporary SQLite file."""
    db = Logger(tmp_path / "test_warden.db")
    yield db
    db.close()


@pytest.fixture()
def policy_path(tmp_path):
    """Write a minimal policy.yaml and return its path."""
    policy = {
        "default_action": "flag",
        "rules": [],
        "network_rules": [
            {
                "match": {"dst_ip": ["0.0.0.0/0"], "dst_port": ["*"]},
                "action": "block",
                "risk": "high",
                "reason": "default-deny all outbound",
            }
        ],
    }
    p = tmp_path / "policy.yaml"
    p.write_text(yaml.dump(policy))
    return p


def _insert_network_flag(logger: Logger, binary: str, destination: str,
                          is_hostname_dest: bool = True, ts: float | None = None,
                          pure_hostname: bool = False,
                          custom_ip: str | None = None,
                          action_id: str | None = None) -> None:
    """Insert a synthetic FLAG network event into the events table."""
    if ts is None:
        ts = time.time()
    from datetime import datetime, timezone
    ts_str = datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    if is_hostname_dest:
        ip_val = None if pure_hostname else (custom_ip or "1.2.3.4")
        parsed_action = json.dumps({
            "binary": binary,
            "raw_input": f"TCP {destination}:443",
            "dst_ip": ip_val,
            "dst_port": 443,
            "protocol": "TCP",
            "hostname_or_sni": destination,
            "direction": "outbound",
        })
    else:
        parsed_action = json.dumps({
            "binary": binary,
            "raw_input": f"TCP {destination}:80",
            "dst_ip": destination,
            "dst_port": 80,
            "protocol": "TCP",
            "hostname_or_sni": None,
            "direction": "outbound",
        })

    with logger._lock:
        logger._conn.execute(
            """
            INSERT INTO events
            (timestamp, session_id, raw_input, event_type, verdict, risk, execution, parsed_action, action_id)
            VALUES (?, ?, ?, 'network', 'FLAG', 'test', 'none', ?, ?)
            """,
            (ts_str, "test-session", "raw", parsed_action, action_id)
        )
        logger._conn.commit()


def _insert_shell_flag(logger: Logger, binary: str, destination: str,
                        ts: float | None = None, action_id: str | None = None,
                        is_hostname_dest: bool = False) -> None:
    """Insert a synthetic FLAG shell event (should NOT be detected by scanner)."""
    if ts is None:
        ts = time.time()
    from datetime import datetime, timezone
    ts_str = datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    action_dict = {
        "binary": binary,
        "args": [],
        "flags": [],
        "target_paths": [],
        "raw_input": binary,
        "sub_commands": [],
    }
    if destination:
        if is_hostname_dest:
            action_dict["hostname_or_sni"] = destination
        else:
            action_dict["dst_ip"] = destination
    parsed_action = json.dumps(action_dict)
    with logger._lock:
        logger._conn.execute(
            """
            INSERT INTO events
                (timestamp, raw_input, parsed_action, event_type, verdict, reason, execution, output, action_id)
            VALUES (?, ?, ?, 'shell_command', 'FLAG', 'test', 'none', '{}', ?)
            """,
            (ts_str, binary, parsed_action, action_id),
        )
        logger._conn.commit()


# ─── Detection Scanner Tests ───────────────────────────────────────────────────

class TestDetectionScanner:

    def test_below_threshold_no_candidates(self, tmp_db):
        """9 events (N-1) must not produce a candidate."""
        for _ in range(9):
            _insert_network_flag(tmp_db, "curl", "evil.example.com")

        candidates = scan(tmp_db, n_threshold=10, window_hours=6.0)
        assert candidates == []

    def test_at_threshold_one_candidate(self, tmp_db):
        """Exactly 10 events must produce exactly one candidate."""
        for _ in range(10):
            _insert_network_flag(tmp_db, "curl", "1.2.3.4", is_hostname_dest=False)

        candidates = scan(tmp_db, n_threshold=10, window_hours=6.0)
        assert len(candidates) == 1
        c = candidates[0]
        assert c.binary == "unknown source"
        assert c.destination == "1.2.3.4"
        assert c.detection_axis == "ip"
        assert c.occurrence_count == 10

    def test_above_threshold_one_candidate(self, tmp_db):
        """11 events (N+1) still produces one candidate with correct count."""
        for _ in range(11):
            _insert_network_flag(tmp_db, "curl", "1.2.3.4", is_hostname_dest=False)

        candidates = scan(tmp_db, n_threshold=10, window_hours=6.0)
        assert len(candidates) == 1
        assert candidates[0].occurrence_count == 11

    def test_window_cutoff_excludes_old_events(self, tmp_db):
        """9 events within window + 1 event older than 6h = still 0 candidates."""
        now = time.time()
        for _ in range(9):
            _insert_network_flag(tmp_db, "curl", "evil.example.com", ts=now)
        # Insert 1 event 7 hours ago (outside the 6h window)
        _insert_network_flag(tmp_db, "curl", "evil.example.com", ts=now - 7 * 3600)

        candidates = scan(tmp_db, n_threshold=10, window_hours=6.0)
        assert candidates == []

    def test_window_cutoff_counts_only_window_events(self, tmp_db):
        """15 total events: 10 within window, 5 outside. Should detect at N=10."""
        now = time.time()
        for _ in range(10):
            _insert_network_flag(tmp_db, "curl", "1.2.3.4", is_hostname_dest=False, ts=now - 1)
        for _ in range(5):
            _insert_network_flag(tmp_db, "curl", "1.2.3.4", is_hostname_dest=False, ts=now - 8 * 3600)

        candidates = scan(tmp_db, n_threshold=10, window_hours=6.0)
        assert len(candidates) == 1
        assert candidates[0].occurrence_count == 10  # Only 10, not 15

    def test_shell_events_without_dest_excluded(self, tmp_db):
        """10 shell FLAG events without a destination must not trigger detection."""
        for _ in range(10):
            _insert_shell_flag(tmp_db, "curl", "")

        candidates = scan(tmp_db, n_threshold=10, window_hours=6.0)
        assert candidates == []

    def test_shell_grouping_respects_binary(self, tmp_db):
        """Two different shell-origin (binary, destination) pairs each at threshold → two candidates."""
        for _ in range(10):
            _insert_shell_flag(tmp_db, "curl", "evil.example.com", is_hostname_dest=True)
        for _ in range(12):
            _insert_shell_flag(tmp_db, "python3", "1.2.3.4", is_hostname_dest=False)

        candidates = scan(tmp_db, n_threshold=10, window_hours=6.0)
        assert len(candidates) == 2
        
        # We expect: (curl, hostname axis), (python3, IP axis)
        axes = {c.detection_axis for c in candidates}
        assert axes == {"hostname", "ip"}
        binaries = {c.binary for c in candidates}
        assert binaries == {"curl", "python3"}

    def test_network_grouping_ignores_binary(self, tmp_db):
        """6 FLAG network events for 'curl' and 6 for 'wget' to same dst_ip -> ONE candidate with 12 counts."""
        for _ in range(6):
            _insert_network_flag(tmp_db, "placeholder", "1.2.3.4", is_hostname_dest=False, action_id="a1")
            _insert_shell_flag(tmp_db, "curl", "", action_id="a1")
        for _ in range(6):
            _insert_network_flag(tmp_db, "placeholder", "1.2.3.4", is_hostname_dest=False, action_id="a2")
            _insert_shell_flag(tmp_db, "wget", "", action_id="a2")

        candidates = scan(tmp_db, n_threshold=10, window_hours=6.0)
        assert len(candidates) == 1
        assert candidates[0].occurrence_count == 12
        assert candidates[0].binary == "multiple sources"
        assert candidates[0].destination == "1.2.3.4"

    def test_network_binary_resolution(self, tmp_db):
        """Test binary resolution branches: single, multiple (covered above), unknown."""
        # Single source
        for _ in range(10):
            _insert_network_flag(tmp_db, "placeholder", "8.8.8.8", is_hostname_dest=False, action_id="a3")
        _insert_shell_flag(tmp_db, "nmap", "", action_id="a3")

        # Unknown source (no shell correlation)
        for _ in range(10):
            _insert_network_flag(tmp_db, "placeholder", "9.9.9.9", is_hostname_dest=False)

        candidates = scan(tmp_db, n_threshold=10, window_hours=6.0)
        # Should find 8.8.8.8 and 9.9.9.9
        assert len(candidates) == 2
        c_nmap = next(c for c in candidates if c.destination == "8.8.8.8")
        assert c_nmap.binary == "nmap"
        c_unknown = next(c for c in candidates if c.destination == "9.9.9.9")
        assert c_unknown.binary == "unknown source"

    def test_resolve_network_binary_failure_isolation(self, tmp_db, monkeypatch):
        """Monkeypatch resolution to fail, confirm candidate still returned as unknown source."""
        def fail_resolve(*args, **kwargs):
            raise RuntimeError("Database error")
        monkeypatch.setattr("daemon.advisor.detection_scanner._resolve_network_binary", fail_resolve)

        # Network events (will encounter exception during binary resolution)
        for _ in range(10):
            _insert_network_flag(tmp_db, "placeholder", "4.4.4.4", is_hostname_dest=False, action_id="a4")
        _insert_shell_flag(tmp_db, "nmap", "", action_id="a4")

        # Shell events (bypasses _resolve_network_binary entirely)
        for _ in range(10):
            _insert_shell_flag(tmp_db, "curl", "evil.example.com", is_hostname_dest=True)

        candidates = scan(tmp_db, n_threshold=10, window_hours=6.0)
        assert len(candidates) == 2
        
        c_net = next(c for c in candidates if c.destination == "4.4.4.4")
        assert c_net.binary == "unknown source"
        
        c_shell = next(c for c in candidates if c.destination == "evil.example.com")
        assert c_shell.binary == "curl"

    def test_ip_destination_detected(self, tmp_db):
        """Events with only dst_ip (no hostname_or_sni) are correctly grouped."""
        for _ in range(10):
            _insert_network_flag(tmp_db, "wget", "9.9.9.9", is_hostname_dest=False)

        candidates = scan(tmp_db, n_threshold=10, window_hours=6.0)
        assert len(candidates) == 1
        assert candidates[0].destination == "9.9.9.9"

    def test_mixed_axes_detected_independently(self, tmp_db):
        """Mirrors the 11-event curl worked example from WARDEN_BUILD_CONTEXT.md.
        8 events dst_ip-only, 3 events with hostname, same dst_ip.
        IP axis crosses N=10 (11 events), hostname axis does not (3 events).
        """
        for _ in range(8):
            _insert_network_flag(tmp_db, "curl", "1.2.3.4", is_hostname_dest=False)
        
        # 3 events with SNI "evil.example.com", which our fixture maps to dst_ip 1.2.3.4
        for _ in range(3):
            _insert_network_flag(tmp_db, "curl", "evil.example.com")

        candidates = scan(tmp_db, n_threshold=10, window_hours=6.0)
        assert len(candidates) == 1
        assert candidates[0].destination == "1.2.3.4"
        assert candidates[0].detection_axis == "ip"
        assert candidates[0].occurrence_count == 11


# ─── Template Engine Tests ─────────────────────────────────────────────────────

class TestTemplateEngine:

    def _make_candidate(self, binary="curl", destination="evil.example.com", count=10):
        now = time.time()
        axis = "hostname" if _is_hostname(destination) else "ip"
        return DetectionCandidate(
            binary=binary,
            destination=destination,
            detection_axis=axis,
            occurrence_count=count,
            window_start=now - 3600,
            window_end=now,
        )

    def test_reasoning_text_contains_all_fields(self):
        candidate = self._make_candidate(binary="curl", destination="evil.com", count=15)
        text = build_reasoning_text(candidate, replay_changed=12, replay_total=20,
                                    n_threshold=10, window_hours=6.0)
        assert "curl" in text
        assert "evil.com" in text
        assert "15" in text
        assert "12" in text
        assert "20" in text
        assert "N=10" in text
        assert "T=6h" in text

    def test_proposed_rule_uses_hostname_key_for_domain(self):
        candidate = self._make_candidate(destination="api.openai.com")
        yaml_str = build_proposed_rule(candidate)
        rule = yaml.safe_load(yaml_str)
        assert "hostname" in rule["match"], "Should use 'hostname' key for domain destination"
        assert "dst_ip" not in rule["match"]

    def test_proposed_rule_uses_dst_ip_key_for_ip(self):
        candidate = self._make_candidate(destination="1.2.3.4")
        yaml_str = build_proposed_rule(candidate)
        rule = yaml.safe_load(yaml_str)
        assert "dst_ip" in rule["match"], "Should use 'dst_ip' key for IP destination"
        assert "hostname" not in rule["match"]

    def test_proposed_rule_parses_as_valid_yaml(self):
        candidate = self._make_candidate()
        yaml_str = build_proposed_rule(candidate)
        rule = yaml.safe_load(yaml_str)
        assert isinstance(rule, dict)
        assert "match" in rule
        assert rule["action"] == "block"

    def test_proposed_rule_action_is_block_not_allow(self):
        """Phase 3 initial build only proposes BLOCK rules — never ALLOW."""
        candidate = self._make_candidate()
        yaml_str = build_proposed_rule(candidate)
        assert not is_permissive(yaml_str)

    def test_is_permissive_false_for_block(self):
        assert not is_permissive("action: block\nmatch:\n  dst_ip: [1.2.3.4]\n")

    def test_is_permissive_true_for_allow(self):
        assert is_permissive("action: allow\nmatch:\n  dst_ip: [1.2.3.4]\n")

    def test_is_hostname_classifies_correctly(self):
        assert _is_hostname("api.openai.com") is True
        assert _is_hostname("evil.example.com") is True
        assert _is_hostname("1.2.3.4") is False
        assert _is_hostname("192.168.1.100") is False


# ─── Dry-Run Replay Tests ──────────────────────────────────────────────────────

class TestDryRunReplay:

    def _candidate(self, binary="curl", destination="evil.example.com"):
        now = time.time()
        axis = "hostname" if _is_hostname(destination) else "ip"
        return DetectionCandidate(
            binary=binary,
            destination=destination,
            detection_axis=axis,
            occurrence_count=10,
            window_start=now - 3600,
            window_end=now,
        )

    def test_replay_correct_figures(self, tmp_db, policy_path):
        """5 FLAG events for the pair → proposed BLOCK rule → changed=5, total=5."""
        candidate = self._candidate()
        # Insert 5 FLAG network events for (curl, evil.example.com)
        for _ in range(5):
            _insert_network_flag(tmp_db, "curl", "evil.example.com")

        proposed_yaml = build_proposed_rule(candidate)
        changed, total = replay(candidate, proposed_yaml, policy_path, tmp_db)
        assert total == 5
        assert changed == 5

    def test_replay_excludes_other_pairs(self, tmp_db, policy_path):
        """ALLOW events for a different destination are excluded from total."""
        candidate = self._candidate(destination="evil.example.com")
        for _ in range(5):
            _insert_network_flag(tmp_db, "curl", "evil.example.com")
        # Insert events for a different destination — should not be counted
        for _ in range(3):
            _insert_network_flag(tmp_db, "curl", "allowed.example.com")

        proposed_yaml = build_proposed_rule(candidate)
        changed, total = replay(candidate, proposed_yaml, policy_path, tmp_db)
        assert total == 5  # Only the 5 evil.example.com events
        assert changed == 5

    def test_replay_axis_isolation(self, tmp_db, policy_path):
        """Replay must strictly filter by the candidate's detection_axis."""
        # Insert 2 events for the SAME hostname, but DIFFERENT IPs
        _insert_network_flag(tmp_db, "curl", "evil.example.com", custom_ip="1.1.1.1")
        _insert_network_flag(tmp_db, "curl", "evil.example.com", custom_ip="2.2.2.2")

        # 1. Replay against hostname axis (should see both events)
        cand_hostname = self._candidate(destination="evil.example.com")
        cand_hostname.detection_axis = "hostname"
        yaml_hostname = build_proposed_rule(cand_hostname)
        _, total_hostname = replay(cand_hostname, yaml_hostname, policy_path, tmp_db)
        assert total_hostname == 2

        # 2. Replay against IP axis for the first IP (should see only 1 event)
        cand_ip = self._candidate(destination="1.1.1.1")
        cand_ip.detection_axis = "ip"
        yaml_ip = build_proposed_rule(cand_ip)
        _, total_ip = replay(cand_ip, yaml_ip, policy_path, tmp_db)
        assert total_ip == 1

    def test_replay_empty_ledger_returns_zeros(self, tmp_db, policy_path):
        """Empty ledger → (0, 0), no errors."""
        candidate = self._candidate()
        proposed_yaml = build_proposed_rule(candidate)
        changed, total = replay(candidate, proposed_yaml, policy_path, tmp_db)
        assert changed == 0
        assert total == 0

    def test_replay_does_not_mutate_policy_yaml(self, tmp_db, policy_path):
        """policy.yaml must be byte-for-byte unchanged after replay()."""
        original_content = policy_path.read_bytes()
        candidate = self._candidate()
        proposed_yaml = build_proposed_rule(candidate)
        replay(candidate, proposed_yaml, policy_path, tmp_db)
        assert policy_path.read_bytes() == original_content, (
            "policy.yaml was mutated by dry_run_replay — this is a safety violation"
        )

    def test_replay_no_temp_files_left(self, tmp_db, policy_path, tmp_path):
        """No warden_replay_*.yaml temp files should persist after replay."""
        candidate = self._candidate()
        proposed_yaml = build_proposed_rule(candidate)
        replay(candidate, proposed_yaml, policy_path, tmp_db)
        import glob, tempfile as _tmp
        leftover = glob.glob(str(Path(_tmp.gettempdir()) / "warden_replay_*.yaml"))
        assert leftover == [], f"Leftover temp files: {leftover}"


# ─── Logger Proposed-Rules Tests ──────────────────────────────────────────────

class TestLoggerProposedRules:

    def _make_proposal(self, **kwargs) -> ProposedRule:
        import uuid
        defaults = dict(
            proposal_id=str(uuid.uuid4()),
            created_at=time.time(),
            detection_rule="exact_match_frequency_v1",
            matched_binary="curl",
            matched_destination="evil.example.com",
            detection_axis="hostname",
            occurrence_count=10,
            window_start=time.time() - 3600,
            window_end=time.time(),
            proposed_yaml_rule="action: block\n",
            status="pending",
            reasoning_text="Test reasoning",
            replay_total=10,
            replay_changed=10,
            permissive_change=0,
        )
        defaults.update(kwargs)
        return ProposedRule(**defaults)

    def test_write_and_list_pending(self, tmp_db):
        p = self._make_proposal()
        tmp_db.write_proposed_rule(p)
        pending = tmp_db.list_pending_proposals()
        assert len(pending) == 1
        assert pending[0]["proposal_id"] == p.proposal_id
        assert pending[0]["matched_binary"] == "curl"
        assert pending[0]["status"] == "pending"

    def test_list_pending_excludes_approved(self, tmp_db):
        p1 = self._make_proposal()
        p2 = self._make_proposal()
        tmp_db.write_proposed_rule(p1)
        tmp_db.write_proposed_rule(p2)
        tmp_db.update_proposal_status(p1.proposal_id, "approved")
        pending = tmp_db.list_pending_proposals()
        assert len(pending) == 1
        assert pending[0]["proposal_id"] == p2.proposal_id

    def test_update_status_approved(self, tmp_db):
        p = self._make_proposal()
        tmp_db.write_proposed_rule(p)
        tmp_db.update_proposal_status(p.proposal_id, "approved")
        row = tmp_db.get_proposal(p.proposal_id)
        assert row["status"] == "approved"

    def test_update_status_rejected(self, tmp_db):
        p = self._make_proposal()
        tmp_db.write_proposed_rule(p)
        tmp_db.update_proposal_status(p.proposal_id, "rejected")
        row = tmp_db.get_proposal(p.proposal_id)
        assert row["status"] == "rejected"

    def test_update_status_invalid_raises(self, tmp_db):
        p = self._make_proposal()
        tmp_db.write_proposed_rule(p)
        with pytest.raises(ValueError, match="invalid status"):
            tmp_db.update_proposal_status(p.proposal_id, "maybe")

    def test_get_proposal_returns_none_for_missing(self, tmp_db):
        assert tmp_db.get_proposal("nonexistent-id") is None

    def test_all_fields_round_trip(self, tmp_db):
        p = self._make_proposal(
            reasoning_text="Round-trip check",
            replay_total=20,
            replay_changed=15,
            permissive_change=0,
            detection_axis="ip",
        )
        tmp_db.write_proposed_rule(p)
        row = tmp_db.get_proposal(p.proposal_id)
        assert row["reasoning_text"] == "Round-trip check"
        assert row["replay_total"] == 20
        assert row["replay_changed"] == 15
        assert row["permissive_change"] == 0
        assert row["detection_axis"] == "ip"

    def test_read_events_for_pair_returns_matching(self, tmp_db):
        _insert_network_flag(tmp_db, "curl", "evil.example.com")
        _insert_network_flag(tmp_db, "curl", "evil.example.com")
        _insert_network_flag(tmp_db, "wget", "other.com")  # different pair
        rows = tmp_db.read_events_for_pair("curl", "evil.example.com")
        assert len(rows) == 2
        for row in rows:
            assert row["verdict"] == "FLAG"


# ─── Approval CLI Gate Tests ───────────────────────────────────────────────────

class TestApprovalCliGate:
    """Tests for the permissive_change gating logic (pure function, no I/O)."""

    def _proposal(self, permissive: bool) -> dict:
        return {"permissive_change": 1 if permissive else 0}

    def test_restrictive_no_flag_allowed(self):
        allowed, msg = check_approve_permissive_gate(self._proposal(False), confirm_permissive=False)
        assert allowed is True
        assert msg == ""

    def test_restrictive_with_flag_allowed(self):
        allowed, msg = check_approve_permissive_gate(self._proposal(False), confirm_permissive=True)
        assert allowed is True

    def test_permissive_without_flag_refused(self):
        allowed, msg = check_approve_permissive_gate(self._proposal(True), confirm_permissive=False)
        assert allowed is False
        assert "--confirm-permissive" in msg

    def test_permissive_with_flag_allowed(self):
        allowed, msg = check_approve_permissive_gate(self._proposal(True), confirm_permissive=True)
        assert allowed is True
        assert msg == ""
