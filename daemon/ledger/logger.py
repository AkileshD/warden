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
    action_id: Optional[str] = None  # Set for ALLOW-dispatched shell events; matched by sidecar for network events

    @property
    def timestamp(self) -> str:
        """ISO-8601 UTC timestamp generated at event creation time."""
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


@dataclass
class ProposedRule:
    """
    CONTRACT: One row in the `proposed_rules` table (schema.sql).

    Written by the Phase 3 advisor (demo/run_phase3_advisor.py) when a
    detection threshold is crossed. Read and actioned by approval_cli.
    Never written by the daemon's real-time interception path.
    """

    proposal_id: str           # UUID4
    created_at: float          # time.time()
    detection_rule: str        # e.g. 'exact_match_frequency_v1'
    matched_binary: str        # e.g. 'curl'
    matched_destination: str   # dst_ip or hostname_or_sni value
    detection_axis: str        # 'ip' or 'hostname'
    occurrence_count: int      # count of FLAGs that triggered this
    window_start: float        # Unix timestamp: earliest matching event
    window_end: float          # Unix timestamp: latest matching event
    proposed_yaml_rule: str    # candidate policy.yaml snippet (YAML string)
    status: str = "pending"    # 'pending' | 'approved' | 'rejected'
    reasoning_text: str = ""   # filled template (human-readable)
    replay_total: int = 0      # B: total historical events matching the rule
    replay_changed: int = 0    # A: events that would have changed verdict
    permissive_change: int = 0 # 1 if proposed rule is ALLOW-expanding, 0 otherwise


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
        """Create the DB and apply the schema if not already present.

        WHY the ALTER TABLE guard exists:
          `CREATE TABLE IF NOT EXISTS` is safe and idempotent for new tables.
          However, it does NOT add new columns to an already-existing table —
          the `action_id` column added to the `events` table in the Phase 3
          compound fix must be applied to databases created before this change
          via an explicit `ALTER TABLE ... ADD COLUMN`. The guard below checks
          for the column's existence and applies the migration only when needed,
          making _initialise() safe to call on both new and existing databases.
        """
        self._db_path.parent.mkdir(parents=True, exist_ok=True)

        schema_path = Path(__file__).parent / "schema.sql"
        if not schema_path.exists():
            raise FileNotFoundError(f"Ledger schema not found at {schema_path}")

        schema_sql = schema_path.read_text()

        with self._lock:
            conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
            conn.execute("PRAGMA journal_mode=WAL")  # WHY WAL: better concurrent read performance
            conn.execute("PRAGMA busy_timeout=5000")  # WHY: prevents SQLITE_BUSY when daemon+sidecar write concurrently
            conn.executescript(schema_sql)

            # Migration guard: add action_id column to events if it doesn't exist yet.
            # Required for databases created before the Phase 3 compound fix.
            existing_cols = {row[1] for row in conn.execute("PRAGMA table_info(events)")}
            if "action_id" not in existing_cols:
                conn.execute("ALTER TABLE events ADD COLUMN action_id TEXT")

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
             verdict, reason, risk, execution, output, action_id)
        VALUES
            (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            event.action_id,
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
                "SELECT * FROM events ORDER BY id ASC"
            )
            cols = [d[0] for d in cursor.description]
            return [dict(zip(cols, row)) for row in cursor.fetchall()]

    # ------------------------------------------------------------------
    # Pending-actions correlation (Phase 3 compound fix)
    # ------------------------------------------------------------------

    def write_pending_action(
        self,
        action_id: str,
        dispatched_at: float,
        binary: str,
        args: str,          # JSON-serialized list
        pid: Optional[int] = None,
        ttl: float = 60.0,
    ) -> None:
        """Write a pending-action row immediately before a real subprocess is launched.

        Called by core.py for ALLOW-dispatched commands only. Never raises.
        """
        import time as _time  # local import avoids adding a module-level dep for a narrow feature
        try:
            expires_at = dispatched_at + ttl
            with self._lock:
                self._conn.execute(
                    "INSERT OR REPLACE INTO pending_actions "
                    "(action_id, dispatched_at, binary, args, pid, expires_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (action_id, dispatched_at, binary, args, pid, expires_at),
                )
                self._conn.commit()
        except Exception as e:
            import sys
            print(f"[warden:logger] ERROR writing pending_action: {e}", file=sys.stderr)

    def update_pending_action_pid(self, action_id: str, pid: int) -> None:
        """Update the pid field on an existing pending_actions row.

        Called by core.py after Popen returns and the subprocess PID is known.
        Never raises.
        """
        try:
            with self._lock:
                self._conn.execute(
                    "UPDATE pending_actions SET pid = ? WHERE action_id = ?",
                    (pid, action_id),
                )
                self._conn.commit()
        except Exception as e:
            import sys
            print(f"[warden:logger] ERROR updating pending_action pid: {e}", file=sys.stderr)

    def resolve_pending_action(
        self,
        packet_timestamp: float,
        window_seconds: float = 5.0,
    ) -> Optional[str]:
        """Return the action_id of the best-matching pending action for a packet.

        Queries for rows where dispatched_at is within ±window_seconds of
        packet_timestamp, not yet expired, ordered by closest timestamp.
        Returns None if no match — callers treat this as an unlinked event.
        Never raises.
        """
        import time as _time
        try:
            now = _time.time()
            lo = packet_timestamp - window_seconds
            hi = packet_timestamp + window_seconds
            with self._lock:
                cursor = self._conn.execute(
                    "SELECT action_id FROM pending_actions "
                    "WHERE dispatched_at BETWEEN ? AND ? AND expires_at > ? "
                    "ORDER BY ABS(dispatched_at - ?) ASC LIMIT 1",
                    (lo, hi, now, packet_timestamp),
                )
                row = cursor.fetchone()
            return row[0] if row else None
        except Exception as e:
            import sys
            print(f"[warden:logger] ERROR resolving pending_action: {e}", file=sys.stderr)
            return None

    def cleanup_pending_actions(self) -> None:
        """Delete expired pending_actions rows (expires_at < now).

        Called by the sidecar on every packet arrival as a cheap GC step.
        Runs under lock. Never raises.
        """
        import time as _time
        try:
            now = _time.time()
            with self._lock:
                self._conn.execute(
                    "DELETE FROM pending_actions WHERE expires_at < ?", (now,)
                )
                self._conn.commit()
        except Exception as e:
            import sys
            print(f"[warden:logger] ERROR cleaning up pending_actions: {e}", file=sys.stderr)

    # ------------------------------------------------------------------
    # Proposed-rules (Phase 3 advisor)
    # ------------------------------------------------------------------

    def write_proposed_rule(self, proposal: "ProposedRule") -> None:  # noqa: F821
        """Insert one ProposedRule row with status='pending'. Never raises."""
        try:
            with self._lock:
                self._conn.execute(
                    """
                    INSERT OR IGNORE INTO proposed_rules (
                        proposal_id, created_at, detection_rule,
                        matched_binary, matched_destination, detection_axis,
                        occurrence_count, window_start, window_end,
                        proposed_yaml_rule, status, reasoning_text,
                        replay_total, replay_changed, permissive_change
                    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        proposal.proposal_id,
                        proposal.created_at,
                        proposal.detection_rule,
                        proposal.matched_binary,
                        proposal.matched_destination,
                        proposal.detection_axis,
                        proposal.occurrence_count,
                        proposal.window_start,
                        proposal.window_end,
                        proposal.proposed_yaml_rule,
                        proposal.status,
                        proposal.reasoning_text,
                        proposal.replay_total,
                        proposal.replay_changed,
                        proposal.permissive_change,
                    ),
                )
                self._conn.commit()
        except Exception as e:
            import sys
            print(f"[warden:logger] ERROR writing proposed_rule: {e}", file=sys.stderr)

    def list_pending_proposals(self) -> list:
        """Return all proposed_rules rows with status='pending', ordered by created_at."""
        with self._lock:
            cursor = self._conn.execute(
                "SELECT * FROM proposed_rules WHERE status = 'pending' ORDER BY created_at ASC"
            )
            cols = [d[0] for d in cursor.description]
            return [dict(zip(cols, row)) for row in cursor.fetchall()]

    def list_all_proposals(self) -> list:
        """Return all proposed_rules rows (any status), ordered by created_at."""
        with self._lock:
            cursor = self._conn.execute(
                "SELECT * FROM proposed_rules ORDER BY created_at ASC"
            )
            cols = [d[0] for d in cursor.description]
            return [dict(zip(cols, row)) for row in cursor.fetchall()]

    def get_proposal(self, proposal_id: str) -> Optional[dict]:
        """Return a single proposed_rules row by proposal_id, or None if not found."""
        with self._lock:
            cursor = self._conn.execute(
                "SELECT * FROM proposed_rules WHERE proposal_id = ?", (proposal_id,)
            )
            cols = [d[0] for d in cursor.description]
            row = cursor.fetchone()
            return dict(zip(cols, row)) if row else None

    def update_proposal_status(self, proposal_id: str, status: str) -> None:
        """Mark a proposal approved or rejected.

        Unlike other Logger methods, this raises ValueError for an invalid
        status — a wrong status string is a programming error in the caller,
        not a transient failure worth swallowing.
        """
        if status not in ("approved", "rejected"):
            raise ValueError(f"update_proposal_status: invalid status {status!r}; must be 'approved' or 'rejected'")
        try:
            with self._lock:
                self._conn.execute(
                    "UPDATE proposed_rules SET status = ? WHERE proposal_id = ?",
                    (status, proposal_id),
                )
                self._conn.commit()
        except Exception as e:
            import sys
            print(f"[warden:logger] ERROR updating proposal status: {e}", file=sys.stderr)

    def read_events_for_pair(self, binary: str, destination: str, detection_axis: str | None = None) -> list:
        """Return all events rows where (binary, destination) matches.

        If detection_axis is 'ip', filters strictly by dst_ip.
        If detection_axis is 'hostname', filters strictly by hostname_or_sni.
        If None, falls back to matching either (legacy behavior).
        """
        with self._lock:
            if detection_axis == "ip":
                sql = """
                    SELECT * FROM events
                    WHERE json_extract(parsed_action, '$.binary') = ?
                      AND json_extract(parsed_action, '$.dst_ip') = ?
                    ORDER BY id ASC
                """
                params = (binary, destination)
            elif detection_axis == "hostname":
                sql = """
                    SELECT * FROM events
                    WHERE json_extract(parsed_action, '$.binary') = ?
                      AND json_extract(parsed_action, '$.hostname_or_sni') = ?
                    ORDER BY id ASC
                """
                params = (binary, destination)
            else:
                sql = """
                    SELECT * FROM events
                    WHERE json_extract(parsed_action, '$.binary') = ?
                      AND (
                          json_extract(parsed_action, '$.hostname_or_sni') = ?
                          OR json_extract(parsed_action, '$.dst_ip') = ?
                      )
                    ORDER BY id ASC
                """
                params = (binary, destination, destination)
                
            cursor = self._conn.execute(sql, params)
            cols = [d[0] for d in cursor.description]
            return [dict(zip(cols, row)) for row in cursor.fetchall()]
