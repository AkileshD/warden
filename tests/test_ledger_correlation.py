"""
tests/test_ledger_correlation.py — Tests for the Phase 3 compound fix.

Covers Step 1 of the implementation breakdown:
  - pending_actions table is created by _initialise()
  - action_id column exists on events table
  - calling _initialise() twice on the same DB does not error
  - historical events rows (written before the fix) survive _initialise() with action_id=NULL

Covers Step 2 (Logger pending_actions methods):
  - write_pending_action: row written with correct fields
  - update_pending_action_pid: pid field updated
  - resolve_pending_action: hit within window, miss outside window, miss on expiry
  - cleanup_pending_actions: expired rows deleted, non-expired rows survive
  - resolve returns None gracefully (no exception) on empty table
  - concurrent write (two Logger instances on same file) does not corrupt

Covers action_id in LedgerEvent / _write():
  - action_id written to events table when set
  - action_id is NULL in events table when not set (None)
"""

from __future__ import annotations

import json
import sqlite3
import tempfile
import threading
import time
from pathlib import Path

import pytest

from daemon.ledger.logger import Logger, LedgerEvent
from daemon.parser.shell_parser import ParsedAction
from daemon.inspectors.base import Decision, Verdict
from daemon.executors.base import ExecutionResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tmp_logger(tmp_path: Path) -> Logger:
    return Logger(db_path=tmp_path / "test_warden.db")


def _minimal_event(action_id: str | None = None) -> LedgerEvent:
    """Build the smallest valid LedgerEvent for insertion tests."""
    action = ParsedAction(
        binary="ls",
        args=["./project"],
        flags=[],
        target_paths=[],
        raw_input="ls ./project",
        sub_commands=[],
    )
    verdict = Verdict(decision=Decision.ALLOW, reason="test rule", source_inspector="test")
    result = ExecutionResult(stdout="file.txt\n", stderr="", exit_code=0,
                             was_real=True, was_fabricated=False)
    return LedgerEvent(
        raw_input="ls ./project",
        parsed_action=action,
        verdict=verdict,
        result=result,
        event_type="shell_command",
        action_id=action_id,
    )


# ---------------------------------------------------------------------------
# Step 1: Schema / _initialise()
# ---------------------------------------------------------------------------

class TestSchemaInit:
    def test_pending_actions_table_created(self, tmp_path):
        logger = _tmp_logger(tmp_path)
        conn = sqlite3.connect(str(tmp_path / "test_warden.db"))
        tables = {row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )}
        assert "pending_actions" in tables, "pending_actions table was not created"
        conn.close()
        logger.close()

    def test_events_table_has_action_id_column(self, tmp_path):
        logger = _tmp_logger(tmp_path)
        conn = sqlite3.connect(str(tmp_path / "test_warden.db"))
        cols = {row[1] for row in conn.execute("PRAGMA table_info(events)")}
        assert "action_id" in cols, "action_id column missing from events table"
        conn.close()
        logger.close()

    def test_initialise_twice_does_not_error(self, tmp_path):
        """Calling _initialise() on an already-initialised DB must be idempotent."""
        logger = _tmp_logger(tmp_path)
        logger.close()
        # Re-open the same DB — _initialise() runs again inside __init__
        logger2 = Logger(db_path=tmp_path / "test_warden.db")
        logger2.close()

    def test_historical_events_survive_reinitialise(self, tmp_path):
        """Pre-existing events rows must survive _initialise() (no DROP, no TRUNCATE)."""
        logger = _tmp_logger(tmp_path)
        logger.record(_minimal_event(action_id=None))
        logger.close()

        # Re-open (triggers _initialise() again, including ALTER TABLE guard)
        logger2 = Logger(db_path=tmp_path / "test_warden.db")
        rows = logger2.read_all()
        assert len(rows) == 1, "Historical row was lost after re-initialise"
        logger2.close()

    def test_alter_table_guard_on_pre_existing_db(self, tmp_path):
        """Simulate a pre-fix database (no action_id column) and confirm the
        ALTER TABLE guard adds it without destroying existing data."""
        db_path = tmp_path / "pre_fix.db"

        # Create DB without action_id column (simulate old schema)
        conn = sqlite3.connect(str(db_path))
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                session_id TEXT,
                raw_input  TEXT NOT NULL,
                parsed_action TEXT NOT NULL,
                event_type TEXT NOT NULL DEFAULT 'shell_command',
                verdict    TEXT NOT NULL,
                reason     TEXT,
                risk       TEXT,
                execution  TEXT NOT NULL,
                output     TEXT
            )
        """)
        conn.execute(
            "INSERT INTO events (timestamp, raw_input, parsed_action, event_type, "
            "verdict, execution) VALUES ('2024-01-01T00:00:00Z', 'ls', '{}', "
            "'shell_command', 'ALLOW', 'real')"
        )
        conn.commit()
        conn.close()

        # Now open with Logger — _initialise() should add action_id column
        logger = Logger(db_path=db_path)
        cols = {row[1] for row in sqlite3.connect(str(db_path)).execute(
            "PRAGMA table_info(events)"
        )}
        assert "action_id" in cols

        # And the original row must still be there
        rows = logger.read_all()
        assert len(rows) == 1
        logger.close()


# ---------------------------------------------------------------------------
# Step 2: Logger pending_actions methods
# ---------------------------------------------------------------------------

class TestWritePendingAction:
    def test_row_written_with_correct_fields(self, tmp_path):
        logger = _tmp_logger(tmp_path)
        now = time.time()
        logger.write_pending_action(
            action_id="abc-123",
            dispatched_at=now,
            binary="ls",
            args=json.dumps(["./project"]),
            pid=9999,
            ttl=60.0,
        )
        conn = sqlite3.connect(str(tmp_path / "test_warden.db"))
        row = conn.execute(
            "SELECT action_id, binary, args, pid, expires_at FROM pending_actions "
            "WHERE action_id = 'abc-123'"
        ).fetchone()
        conn.close()
        logger.close()

        assert row is not None
        assert row[0] == "abc-123"
        assert row[1] == "ls"
        assert row[2] == json.dumps(["./project"])
        assert row[3] == 9999
        assert abs(row[4] - (now + 60.0)) < 0.01

    def test_pid_starts_null(self, tmp_path):
        logger = _tmp_logger(tmp_path)
        now = time.time()
        logger.write_pending_action("no-pid", now, "echo", "[]")
        conn = sqlite3.connect(str(tmp_path / "test_warden.db"))
        pid = conn.execute(
            "SELECT pid FROM pending_actions WHERE action_id = 'no-pid'"
        ).fetchone()[0]
        conn.close()
        logger.close()
        assert pid is None


class TestUpdatePendingActionPid:
    def test_pid_updated(self, tmp_path):
        logger = _tmp_logger(tmp_path)
        now = time.time()
        logger.write_pending_action("upd-1", now, "cat", "[]")
        logger.update_pending_action_pid("upd-1", 12345)

        conn = sqlite3.connect(str(tmp_path / "test_warden.db"))
        pid = conn.execute(
            "SELECT pid FROM pending_actions WHERE action_id = 'upd-1'"
        ).fetchone()[0]
        conn.close()
        logger.close()
        assert pid == 12345

    def test_update_nonexistent_row_does_not_raise(self, tmp_path):
        logger = _tmp_logger(tmp_path)
        # Should not raise — never-raises contract
        logger.update_pending_action_pid("ghost-id", 1)
        logger.close()


class TestResolvePendingAction:
    def test_hit_within_window(self, tmp_path):
        logger = _tmp_logger(tmp_path)
        now = time.time()
        logger.write_pending_action("hit-1", now, "python3", "[]", ttl=60.0)
        # packet arrives 1 second later (within 5s window)
        result = logger.resolve_pending_action(now + 1.0, window_seconds=5.0)
        logger.close()
        assert result == "hit-1"

    def test_miss_outside_window(self, tmp_path):
        logger = _tmp_logger(tmp_path)
        now = time.time()
        logger.write_pending_action("miss-1", now - 100.0, "python3", "[]", ttl=200.0)
        # packet arrives 100s after dispatch (outside 5s window)
        result = logger.resolve_pending_action(now, window_seconds=5.0)
        logger.close()
        assert result is None

    def test_miss_on_expiry(self, tmp_path):
        logger = _tmp_logger(tmp_path)
        now = time.time()
        # Write a row that expires in the past (ttl=-1)
        logger.write_pending_action("expired-1", now, "curl", "[]", ttl=-1.0)
        result = logger.resolve_pending_action(now, window_seconds=5.0)
        logger.close()
        assert result is None, "Expired row should not be returned"

    def test_returns_closest_match(self, tmp_path):
        logger = _tmp_logger(tmp_path)
        now = time.time()
        logger.write_pending_action("far",   now - 4.0, "ls", "[]", ttl=60.0)
        logger.write_pending_action("close", now - 0.5, "ls", "[]", ttl=60.0)
        result = logger.resolve_pending_action(now, window_seconds=5.0)
        logger.close()
        assert result == "close", "Should return the closest-timestamp match"

    def test_returns_none_on_empty_table(self, tmp_path):
        logger = _tmp_logger(tmp_path)
        result = logger.resolve_pending_action(time.time())
        logger.close()
        assert result is None


class TestCleanupPendingActions:
    def test_expired_rows_deleted(self, tmp_path):
        logger = _tmp_logger(tmp_path)
        now = time.time()
        logger.write_pending_action("old", now - 200.0, "ls", "[]", ttl=1.0)   # expired
        logger.write_pending_action("new", now,         "ls", "[]", ttl=60.0)  # not expired
        logger.cleanup_pending_actions()

        conn = sqlite3.connect(str(tmp_path / "test_warden.db"))
        ids = {r[0] for r in conn.execute("SELECT action_id FROM pending_actions")}
        conn.close()
        logger.close()
        assert "old" not in ids, "Expired row should have been deleted"
        assert "new" in ids, "Non-expired row should survive cleanup"

    def test_cleanup_on_empty_table_does_not_raise(self, tmp_path):
        logger = _tmp_logger(tmp_path)
        logger.cleanup_pending_actions()  # must not raise
        logger.close()


class TestConcurrentWriters:
    def test_two_loggers_on_same_file_do_not_corrupt(self, tmp_path):
        """Open two Logger instances on the same DB and interleave writes."""
        db_path = tmp_path / "concurrent.db"
        logger_a = Logger(db_path=db_path)
        logger_b = Logger(db_path=db_path)

        errors: list[str] = []

        def write_a():
            for i in range(20):
                try:
                    now = time.time()
                    logger_a.write_pending_action(
                        f"a-{i}", now, "ls", "[]", ttl=60.0
                    )
                except Exception as e:
                    errors.append(f"a-{i}: {e}")

        def write_b():
            for i in range(20):
                try:
                    now = time.time()
                    logger_b.write_pending_action(
                        f"b-{i}", now, "cat", "[]", ttl=60.0
                    )
                except Exception as e:
                    errors.append(f"b-{i}: {e}")

        t1 = threading.Thread(target=write_a)
        t2 = threading.Thread(target=write_b)
        t1.start(); t2.start()
        t1.join(); t2.join()

        logger_a.close()
        logger_b.close()

        assert errors == [], f"Concurrent write errors: {errors}"

        # Confirm all 40 rows exist
        conn = sqlite3.connect(str(db_path))
        count = conn.execute("SELECT COUNT(*) FROM pending_actions").fetchone()[0]
        conn.close()
        assert count == 40, f"Expected 40 rows, got {count}"


# ---------------------------------------------------------------------------
# action_id in LedgerEvent / events INSERT
# ---------------------------------------------------------------------------

class TestActionIdInEvents:
    def test_action_id_written_to_events(self, tmp_path):
        logger = _tmp_logger(tmp_path)
        logger.record(_minimal_event(action_id="test-uuid-1234"))
        conn = sqlite3.connect(str(tmp_path / "test_warden.db"))
        action_id = conn.execute(
            "SELECT action_id FROM events ORDER BY id DESC LIMIT 1"
        ).fetchone()[0]
        conn.close()
        logger.close()
        assert action_id == "test-uuid-1234"

    def test_action_id_null_when_not_set(self, tmp_path):
        logger = _tmp_logger(tmp_path)
        logger.record(_minimal_event(action_id=None))
        conn = sqlite3.connect(str(tmp_path / "test_warden.db"))
        action_id = conn.execute(
            "SELECT action_id FROM events ORDER BY id DESC LIMIT 1"
        ).fetchone()[0]
        conn.close()
        logger.close()
        assert action_id is None
