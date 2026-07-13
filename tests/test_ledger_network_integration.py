"""
tests/test_ledger_network_integration.py — Integration test: network events in the Ledger.

PURPOSE: Verify that the existing Ledger schema (schema.sql) and logger (logger.py)
correctly round-trip a ParsedNetworkAction + Verdict without any schema migration.

What this test proves:
  1. Schema: zero changes needed. The `event_type` TEXT column and `parsed_action`
     TEXT (JSON blob) column already exist in schema.sql and are sufficient.
     CREATE TABLE IF NOT EXISTS is idempotent — no migration required.
  2. Logger: one minimal change was required (see logger.py _serialise_parsed_action).
     Without it, the base ParsedAction branch would silently drop all network-specific
     fields (dst_ip, dst_port, protocol, hostname_or_sni, direction) because
     ParsedNetworkAction IS-A ParsedAction and would match the generic branch first.
     The fix: an isinstance(action, ParsedNetworkAction) check before the generic branch.
  3. Round-trip fidelity: the JSON blob written to parsed_action can be deserialised
     and all network fields are present with correct values.
  4. Discriminator: event_type="network" is correctly stored and readable.
  5. Verdict fields (verdict, reason) are correctly stored.
  6. Shell command events are unaffected — existing serialisation is unchanged.

WHY use a temp file (tmp_path fixture) and not :memory::
  Logger.__init__ calls _initialise() which reads schema.sql from the filesystem
  (Path(__file__).parent / "schema.sql"). An in-memory connection would work for
  the DB itself, but Logger's constructor always creates a file-based connection.
  tmp_path gives us a real temp file that pytest cleans up automatically.
"""

import json
import tempfile
from pathlib import Path
from typing import Optional

import pytest

from daemon.ledger.logger import LedgerEvent, Logger
from daemon.inspectors.base import Decision, Verdict
from daemon.parser.packet_parser import ParsedNetworkAction
from daemon.parser.shell_parser import ParsedAction
from daemon.executors.base import ExecutionResult


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def tmp_db(tmp_path: Path) -> Path:
    """Return a path to a temporary SQLite database file."""
    return tmp_path / "test_warden.db"


@pytest.fixture
def logger(tmp_db: Path) -> Logger:
    """Construct a Logger backed by a temp SQLite file."""
    lg = Logger(db_path=tmp_db)
    yield lg
    lg.close()


def _make_network_action(
    dst_ip: str = "93.184.216.34",
    dst_port: int = 443,
    protocol: str = "TCP",
    hostname_or_sni: Optional[str] = "api.openai.com",
    direction: str = "outbound",
) -> ParsedNetworkAction:
    return ParsedNetworkAction(
        binary="<network>",
        raw_input=f"{protocol} {dst_ip}:{dst_port}",
        dst_ip=dst_ip,
        dst_port=dst_port,
        protocol=protocol,
        hostname_or_sni=hostname_or_sni,
        raw_bytes=b"\x00\x01\x02",  # synthetic — should NOT appear in ledger
        direction=direction,
    )


def _make_verdict(decision: Decision = Decision.BLOCK) -> Verdict:
    return Verdict(
        decision=decision,
        reason="test verdict reason",
        source_inspector="NetworkInspector",
    )


def _make_result(*, blocked: bool = True) -> ExecutionResult:
    """Network events always produce a 'none' execution result — no subprocess ran."""
    return ExecutionResult(
        stdout="",
        stderr="",
        exit_code=0,
        was_real=False,
        was_fabricated=False,
    )


def _read_all_rows(logger: Logger) -> list[dict]:
    """Read every row from the ledger, including event_type and parsed_action."""
    with logger._lock:
        cursor = logger._conn.execute(
            "SELECT id, timestamp, raw_input, event_type, parsed_action, "
            "verdict, reason, execution FROM events ORDER BY id ASC"
        )
        cols = [d[0] for d in cursor.description]
        return [dict(zip(cols, row)) for row in cursor.fetchall()]


# ── Test: schema already handles network events (no migration) ────────────────

class TestSchemaCompatibility:
    """The existing schema (schema.sql) requires zero changes for network events."""

    def test_event_type_column_exists(self, logger: Logger):
        """Verify the events table has an event_type column (it should, from Phase 1)."""
        with logger._lock:
            cursor = logger._conn.execute("PRAGMA table_info(events)")
            columns = {row[1] for row in cursor.fetchall()}
        assert "event_type" in columns, (
            "Schema requires event_type column — it was present since schema.sql was written "
            "with Phase 2 in mind. No migration needed."
        )

    def test_parsed_action_column_exists(self, logger: Logger):
        """Verify parsed_action column (JSON blob) exists."""
        with logger._lock:
            cursor = logger._conn.execute("PRAGMA table_info(events)")
            columns = {row[1] for row in cursor.fetchall()}
        assert "parsed_action" in columns

    def test_no_network_specific_columns_needed(self, logger: Logger):
        """Network fields (dst_ip, dst_port, etc.) live in the JSON blob — no new columns."""
        with logger._lock:
            cursor = logger._conn.execute("PRAGMA table_info(events)")
            columns = {row[1] for row in cursor.fetchall()}
        # These must NOT be separate columns — they're in the JSON blob.
        for col in ("dst_ip", "dst_port", "hostname_or_sni", "protocol"):
            assert col not in columns, (
                f"Column {col!r} should NOT exist as a separate column — "
                "network fields are stored in the parsed_action JSON blob."
            )


# ── Test: write + read round-trip ─────────────────────────────────────────────

class TestNetworkEventRoundTrip:
    """Write a network LedgerEvent, read it back, confirm all fields."""

    def test_event_type_discriminator_stored(self, logger: Logger):
        """event_type='network' is stored and readable."""
        action = _make_network_action()
        event = LedgerEvent(
            raw_input=action.raw_input,
            parsed_action=action,
            verdict=_make_verdict(),
            result=_make_result(),
            event_type="network",
        )
        logger.record(event)
        rows = _read_all_rows(logger)
        assert len(rows) == 1
        assert rows[0]["event_type"] == "network"

    def test_parsed_action_json_blob_round_trip(self, logger: Logger):
        """All network-specific fields survive the JSON round-trip."""
        action = _make_network_action(
            dst_ip="8.8.8.8",
            dst_port=53,
            protocol="UDP",
            hostname_or_sni="api.example.com",
            direction="outbound",
        )
        event = LedgerEvent(
            raw_input=action.raw_input,
            parsed_action=action,
            verdict=_make_verdict(Decision.BLOCK),
            result=_make_result(),
            event_type="network",
        )
        logger.record(event)
        rows = _read_all_rows(logger)
        blob = json.loads(rows[0]["parsed_action"])

        assert blob["dst_ip"] == "8.8.8.8"
        assert blob["dst_port"] == 53
        assert blob["protocol"] == "UDP"
        assert blob["hostname_or_sni"] == "api.example.com"
        assert blob["direction"] == "outbound"
        assert blob["binary"] == "<network>"

    def test_raw_bytes_not_in_json_blob(self, logger: Logger):
        """raw_bytes must NOT appear in the JSON blob — it's binary and large."""
        action = _make_network_action()
        event = LedgerEvent(
            raw_input=action.raw_input,
            parsed_action=action,
            verdict=_make_verdict(),
            result=_make_result(),
            event_type="network",
        )
        logger.record(event)
        rows = _read_all_rows(logger)
        blob = json.loads(rows[0]["parsed_action"])
        assert "raw_bytes" not in blob, (
            "raw_bytes must be excluded from the ledger JSON blob — "
            "it is binary, potentially large, and reconstructable from NFQUEUE."
        )

    def test_verdict_stored_correctly(self, logger: Logger):
        """verdict and reason columns are correctly populated for network events."""
        action = _make_network_action()
        verdict = Verdict(
            decision=Decision.BLOCK,
            reason="no network_rule matched 93.184.216.34:443 → BLOCK (default-deny)",
            source_inspector="NetworkInspector",
        )
        event = LedgerEvent(
            raw_input=action.raw_input,
            parsed_action=action,
            verdict=verdict,
            result=_make_result(),
            event_type="network",
        )
        logger.record(event)
        rows = _read_all_rows(logger)
        assert rows[0]["verdict"] == "BLOCK"
        assert "default-deny" in rows[0]["reason"]

    def test_allow_verdict_stored(self, logger: Logger):
        """ALLOW verdicts for allowlisted hosts are correctly stored."""
        action = _make_network_action(hostname_or_sni="api.openai.com")
        verdict = Verdict(
            decision=Decision.ALLOW,
            reason="network_rule matched: TCP 93.184.216.34:443 hostname='api.openai.com' → ALLOW (risk=low)",
            source_inspector="NetworkInspector",
        )
        event = LedgerEvent(
            raw_input=action.raw_input,
            parsed_action=action,
            verdict=verdict,
            result=_make_result(blocked=False),
            event_type="network",
        )
        logger.record(event)
        rows = _read_all_rows(logger)
        assert rows[0]["verdict"] == "ALLOW"

    def test_hostname_none_round_trips_as_null(self, logger: Logger):
        """hostname_or_sni=None (plain TCP, no SNI) must round-trip as JSON null."""
        action = _make_network_action(hostname_or_sni=None)
        event = LedgerEvent(
            raw_input=action.raw_input,
            parsed_action=action,
            verdict=_make_verdict(),
            result=_make_result(),
            event_type="network",
        )
        logger.record(event)
        rows = _read_all_rows(logger)
        blob = json.loads(rows[0]["parsed_action"])
        # json.loads turns JSON null → Python None
        assert blob["hostname_or_sni"] is None

    def test_execution_field_is_none_for_network_events(self, logger: Logger):
        """Network events produce execution='none' — no subprocess was run."""
        action = _make_network_action()
        event = LedgerEvent(
            raw_input=action.raw_input,
            parsed_action=action,
            verdict=_make_verdict(),
            result=ExecutionResult(
                stdout="", stderr="", exit_code=0,
                was_real=False, was_fabricated=False,
            ),
            event_type="network",
        )
        logger.record(event)
        rows = _read_all_rows(logger)
        assert rows[0]["execution"] == "none"

    def test_raw_input_stored(self, logger: Logger):
        """raw_input column holds the human-readable packet summary."""
        action = _make_network_action(dst_ip="8.8.8.8", dst_port=443, protocol="TCP")
        event = LedgerEvent(
            raw_input=action.raw_input,
            parsed_action=action,
            verdict=_make_verdict(),
            result=_make_result(),
            event_type="network",
        )
        logger.record(event)
        rows = _read_all_rows(logger)
        assert "TCP" in rows[0]["raw_input"]
        assert "8.8.8.8" in rows[0]["raw_input"]


# ── Test: mixed shell + network events in same ledger ─────────────────────────

class TestMixedEvents:
    """Shell command and network events coexist in the same ledger table."""

    def test_mixed_event_types_in_one_ledger(self, logger: Logger):
        """A ledger can hold both shell_command and network rows side-by-side."""
        # Write a shell command event (Phase 1 style)
        shell_action = ParsedAction(binary="ls", args=["./project"], raw_input="ls ./project")
        shell_verdict = Verdict(decision=Decision.ALLOW, reason="Rule 5 matched", source_inspector="CommandInspector")
        shell_result = ExecutionResult(stdout="main.py", stderr="", exit_code=0, was_real=True, was_fabricated=False)
        shell_event = LedgerEvent(
            raw_input="ls ./project",
            parsed_action=shell_action,
            verdict=shell_verdict,
            result=shell_result,
            event_type="shell_command",
        )
        logger.record(shell_event)

        # Write a network event (Phase 2 style)
        net_action = _make_network_action(dst_ip="1.2.3.4", dst_port=443, hostname_or_sni="evil.com")
        net_event = LedgerEvent(
            raw_input=net_action.raw_input,
            parsed_action=net_action,
            verdict=_make_verdict(Decision.BLOCK),
            result=_make_result(),
            event_type="network",
        )
        logger.record(net_event)

        rows = _read_all_rows(logger)
        assert len(rows) == 2

        shell_row = rows[0]
        net_row = rows[1]

        assert shell_row["event_type"] == "shell_command"
        assert net_row["event_type"] == "network"

        # Shell blob has the shell structure
        shell_blob = json.loads(shell_row["parsed_action"])
        assert "binary" in shell_blob
        assert "args" in shell_blob
        assert "dst_ip" not in shell_blob

        # Network blob has the network structure
        net_blob = json.loads(net_row["parsed_action"])
        assert "dst_ip" in net_blob
        assert net_blob["hostname_or_sni"] == "evil.com"
        assert "args" not in net_blob

    def test_shell_serialisation_unchanged(self, logger: Logger):
        """Writing a shell event after the logger.py change still produces the correct blob."""
        shell_action = ParsedAction(
            binary="rm", args=["/etc/passwd"], flags=["-rf"],
            raw_input="rm -rf /etc/passwd",
        )
        shell_event = LedgerEvent(
            raw_input="rm -rf /etc/passwd",
            parsed_action=shell_action,
            verdict=Verdict(decision=Decision.BLOCK, reason="Rule 1", source_inspector="CommandInspector"),
            result=ExecutionResult(stdout="", stderr="", exit_code=1, was_real=False, was_fabricated=True),
            event_type="shell_command",
        )
        logger.record(shell_event)
        rows = _read_all_rows(logger)
        blob = json.loads(rows[0]["parsed_action"])

        assert blob["binary"] == "rm"
        assert "/etc/passwd" in blob["args"]
        assert "-rf" in blob["flags"]
        assert "dst_ip" not in blob
