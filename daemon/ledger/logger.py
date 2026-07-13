"""
daemon/ledger/logger.py — Write-only ledger logger for Warden.

CONTRACT: Logger.record(event: LedgerEvent) -> None
  Writes one row to the SQLite ledger per call. Never reads.
  Never raises (logs internal errors to stderr and continues).

WHY write-only: the Logger is the only component that writes to the ledger.
  The dashboard and CLI viewers read from it directly (no API, no Logger
  involvement). This separation means the Logger can be replaced with a
  different backend (Postgres, an event bus) without touching any viewer.
  See WARDEN_SPEC.md §3: "the Ledger is the only thing the viewers know about."

WHY one connection per Logger instance: SQLite in WAL mode supports concurrent
  readers but only one writer at a time. For Phase 1 (single-agent, single-session),
  a single connection with thread-locking is sufficient and simple.
  TODO(phase2): evaluate connection pooling or a dedicated writer thread if
  multi-agent use is validated.

WHY store parsed_action as JSON: the schema uses a generic JSON blob so that
  future event types (network, file ops) can store different structure without
  a schema migration. The consumer deserialises based on event_type.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ..parser.shell_parser import ParsedAction
from ..inspectors.base import Decision, Verdict
from ..executors.base import ExecutionResult

# Imported here for the isinstance check in _serialise_parsed_action.
# WHY not at the top level: avoids a circular import risk if packet_parser
# ever imports from logger. The isinstance check is the only use.
from ..parser.packet_parser import ParsedNetworkAction


@dataclass
class LedgerEvent:
    """
    CONTRACT: The data written to the ledger for every processed action.

    Maps 1-to-1 to a row in the `events` table (schema.sql).
    All fields except session_id are required for Phase 1.
    """

    raw_input: str
    parsed_action: ParsedAction
    verdict: Verdict
    result: ExecutionResult
    event_type: str = "shell_command"
    session_id: Optional[str] = None
    risk: Optional[str] = None

    @property
    def timestamp(self) -> str:
        """ISO-8601 UTC timestamp generated at event creation time."""
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _serialise_parsed_action(action: ParsedAction) -> str:
    """Convert ParsedAction (or a subclass) to a JSON string for ledger storage.

    WHY custom serializer (not dataclasses.asdict): ParsedAction contains
    Path objects and nested ParsedAction sub_commands, neither of which
    json.dumps handles by default. We convert manually to ensure correctness.

    WHY a ParsedNetworkAction branch exists here:
      _serialise_parsed_action originally serialised only the base ParsedAction
      fields (binary, args, flags, target_paths, raw_input, sub_commands).
      ParsedNetworkAction is a subclass and passes isinstance(action, ParsedAction),
      so it would silently reach the base branch and lose all network-specific
      fields (dst_ip, dst_port, protocol, hostname_or_sni, direction, raw_bytes).
      Without this branch the JSON blob stored for a network event would be
      indistinguishable from a zero-arg shell command — the event_type discriminator
      would be set correctly but the blob would be useless for network forensics.

      The fix is the minimum viable change: detect ParsedNetworkAction first
      (before the generic branch) and emit its concrete fields. raw_bytes is
      excluded from the JSON blob — it is large, binary, and can be reconstructed
      from the NFQUEUE callback if needed; storing it would bloat the ledger.
    """

    if isinstance(action, ParsedNetworkAction):
        # Network event — serialise the network-specific fields.
        return json.dumps({
            "binary": action.binary,           # "<network>" — marker for log display
            "raw_input": action.raw_input,      # human-readable summary e.g. "TCP 8.8.8.8:443"
            "dst_ip": action.dst_ip,
            "dst_port": action.dst_port,
            "protocol": action.protocol,        # "TCP" | "UDP" | "OTHER"
            "hostname_or_sni": action.hostname_or_sni,  # may be None
            "direction": action.direction,      # "outbound" | "inbound"
            # raw_bytes intentionally excluded — binary, large, reconstructable.
        })

    def action_to_dict(a: ParsedAction) -> dict:
        return {
            "binary": a.binary,
            "args": a.args,
            "flags": a.flags,
            "target_paths": [str(p) for p in a.target_paths],
            "raw_input": a.raw_input,
            "sub_commands": [action_to_dict(s) for s in a.sub_commands],
        }

    return json.dumps(action_to_dict(action))


class Logger:
    """
    CONTRACT: implements Logger.record() — see daemon/ledger/logger.py docstring.

    Usage:
        logger = Logger(db_path=Path("warden.db"))
        logger.record(event)
    """

    def __init__(self, db_path: Path) -> None:
        self._db_path = Path(db_path)
        self._lock = threading.Lock()
        self._conn: Optional[sqlite3.Connection] = None
        self._initialise()

    def record(self, event: LedgerEvent) -> None:
        """Write one LedgerEvent to the SQLite ledger.

        CONTRACT: Never raises. On error, prints to stderr and continues —
        a logging failure must never crash the daemon's interception path.
        """
        try:
            self._write(event)
        except Exception as e:
            # RISK: if the ledger is unavailable (disk full, permissions), events
            # are silently dropped after printing to stderr. The daemon continues
            # operating but the audit trail has a gap. TODO(phase2): implement
            # an in-memory ring buffer as a fallback for ledger-unavailable conditions.
            import sys
            print(f"[warden:logger] ERROR writing to ledger: {e}", file=sys.stderr)

    def close(self) -> None:
        """Close the database connection cleanly."""
        with self._lock:
            if self._conn:
                self._conn.close()
                self._conn = None

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _initialise(self) -> None:
        """Create the DB and apply the schema if not already present."""
        self._db_path.parent.mkdir(parents=True, exist_ok=True)

        schema_path = Path(__file__).parent / "schema.sql"
        if not schema_path.exists():
            raise FileNotFoundError(f"Ledger schema not found at {schema_path}")

        schema_sql = schema_path.read_text()

        with self._lock:
            conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
            conn.execute("PRAGMA journal_mode=WAL")  # WHY WAL: better concurrent read performance
            conn.executescript(schema_sql)
            conn.commit()
            self._conn = conn

    def _write(self, event: LedgerEvent) -> None:
        """Execute the INSERT under lock."""
        execution_str = "real" if event.result.was_real else "fake" if event.result.was_fabricated else "none"
        output_json = json.dumps({
            "stdout": event.result.stdout,
            "stderr": event.result.stderr,
            "exit_code": event.result.exit_code,
        })

        sql = """
        INSERT INTO events
            (timestamp, session_id, raw_input, parsed_action, event_type,
             verdict, reason, risk, execution, output)
        VALUES
            (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        params = (
            event.timestamp,
            event.session_id,
            event.raw_input,
            _serialise_parsed_action(event.parsed_action),
            event.event_type,
            event.verdict.decision.value,
            event.verdict.reason,
            event.risk,
            execution_str,
            output_json,
        )

        with self._lock:
            self._conn.execute(sql, params)
            self._conn.commit()

    def read_all(self) -> list[dict]:
        """Read all ledger rows as a list of dicts. For CLI/demo use only.

        WHY this method is on Logger at all: the CLI viewer and demo script need
        to read the ledger. In production the viewer reads SQLite directly; for
        the demo, having a read method here avoids duplicating the DB path logic.
        This method would be removed or moved to a dedicated Reader class in
        Phase 4 when the CLI viewer is a proper separate binary.
        TODO(phase4): move read access to clients/cli/ reader class.
        """
        with self._lock:
            cursor = self._conn.execute(
                "SELECT id, timestamp, raw_input, verdict, reason, execution, output "
                "FROM events ORDER BY id ASC"
            )
            cols = [d[0] for d in cursor.description]
            return [dict(zip(cols, row)) for row in cursor.fetchall()]
