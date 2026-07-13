-- daemon/ledger/schema.sql — Warden unified event ledger schema
--
-- WHY generic column names (not shell-specific): this same table must be able
-- to log Phase 2 network events without a schema migration. Column names like
-- "command" or "shell_command" would make that awkward. Instead, `event_type`
-- is a discriminator string ("shell_command", "network_call", etc.) and
-- `parsed_action` is a JSON blob whose internal shape varies by event_type.
-- This mirrors the EAV / discriminated-union approach common in append-only logs.
--
-- WHY SQLite: zero-ops, file-based, sufficient for single-agent local use.
-- See WARDEN_SPEC.md §10. Evaluate Postgres only if multi-agent concurrency demands it.
--
-- WHY no foreign keys / no normalization: the ledger is an append-only audit log.
-- Normalizing it (e.g. a separate "sessions" table) would complicate queries
-- for the dashboard viewer without meaningful benefit. Flat rows are fast to
-- write and trivial to read.

CREATE TABLE IF NOT EXISTS events (
    -- Identity
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT    NOT NULL,           -- ISO-8601 UTC, e.g. "2024-01-15T10:30:00Z"
    session_id      TEXT,                       -- TODO(phase2): set when multi-session is added

    -- The raw and parsed action
    raw_input       TEXT    NOT NULL,           -- Exactly what the agent sent
    parsed_action   TEXT    NOT NULL,           -- JSON blob; schema varies by event_type
    event_type      TEXT    NOT NULL DEFAULT 'shell_command',
                                                -- Discriminator: "shell_command" | "network_call" (phase2) | etc.

    -- Decision
    verdict         TEXT    NOT NULL,           -- "ALLOW" | "BLOCK" | "FLAG"
    reason          TEXT,                       -- Human-readable explanation from Rule Engine
    risk            TEXT,                       -- "low" | "medium" | "high" | null

    -- Execution outcome
    execution       TEXT    NOT NULL,           -- "real" | "fake" | "none" (if error before exec)
    output          TEXT                        -- JSON: {"stdout": "...", "stderr": "...", "exit_code": 0}
);

-- Index for time-range queries (dashboard live view, Phase 4)
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);

-- Index for filtering by verdict (BLOCK/FLAG view in dashboard)
CREATE INDEX IF NOT EXISTS idx_events_verdict ON events(verdict);

-- Index for session grouping (Phase 2+)
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
