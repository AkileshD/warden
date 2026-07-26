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
    output          TEXT,                       -- JSON: {"stdout": "...", "stderr": "...", "exit_code": 0}

    -- Correlation (Phase 3 compound fix)
    action_id       TEXT                        -- UUID matching a pending_actions row; NULL for pre-fix rows and unmatched network events
);

-- Index for time-range queries (dashboard live view, Phase 4)
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);

-- Index for filtering by verdict (BLOCK/FLAG view in dashboard)
CREATE INDEX IF NOT EXISTS idx_events_verdict ON events(verdict);

-- Index for session grouping (Phase 2+)
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);

-- ── pending_actions ──────────────────────────────────────────────────────────
-- Correlation table written by the daemon at real-dispatch time and read by
-- the network sidecar when a packet arrives.
--
-- WHY a separate table (not a column on events): pending_actions rows are
-- short-lived (TTL ~60s) and written BEFORE the final LedgerEvent row exists.
-- The daemon writes here at Popen time; the sidecar reads and GC-cleans here
-- independently. Mixing this into `events` would complicate the append-only
-- audit-log contract. Expired rows are deleted by the sidecar on each packet.
--
-- WHY REAL for dispatched_at / expires_at: SQLite stores these as float seconds
-- since Unix epoch, giving millisecond precision without a text-parsing round-
-- trip. Compared using plain arithmetic in the sidecar's resolve query.

CREATE TABLE IF NOT EXISTS pending_actions (
    action_id     TEXT PRIMARY KEY,
    dispatched_at REAL NOT NULL,   -- time.time() at Popen call, millisecond precision
    binary        TEXT NOT NULL,
    args          TEXT NOT NULL,   -- JSON-serialized list, e.g. '["ls", "./project"]'
    pid           INTEGER,         -- subprocess PID; set after Popen returns (may be NULL)
    expires_at    REAL NOT NULL    -- dispatched_at + TTL_SECONDS (default 60.0)
);

-- Index for the sidecar's time-window query (dispatched_at BETWEEN lo AND hi)
CREATE INDEX IF NOT EXISTS idx_pending_actions_dispatched
    ON pending_actions(dispatched_at);

-- ── proposed_rules ────────────────────────────────────────────────────────────
-- Written by the Phase 3 advisor when a detection threshold is crossed.
-- Read by the approval CLI. Never written by the daemon's hot path.
--
-- WHY same database (not a separate file): consistent with the single-writer
-- principle from Phase 2's correlation fix. The daemon process owns this DB;
-- the advisor script and approval CLI are the only other accessors, and they
-- access it read-mostly (scan+list) or with low-frequency single-row updates
-- (approve/reject). No concurrency concern.
--
-- WHY replay_total/replay_changed as stored columns (not recomputed):
-- The dry-run replay runs once at proposal generation time against the ledger
-- as it existed then. Re-running later would give different numbers as the
-- ledger grows, producing inconsistent "evidence" for the same proposal.
-- Storing them makes the proposal's evidence immutable.
--
-- WHY permissive_change as INTEGER (not derived from proposed_yaml_rule):
-- Avoids re-parsing the YAML string at approval time. The approval CLI reads
-- this column to decide whether the asymmetric-scrutiny path applies.

CREATE TABLE IF NOT EXISTS proposed_rules (
    proposal_id         TEXT    PRIMARY KEY,    -- UUID4
    created_at          REAL    NOT NULL,       -- time.time() at proposal generation
    detection_rule      TEXT    NOT NULL,       -- e.g. 'exact_match_frequency_v1'
    matched_binary      TEXT    NOT NULL,       -- e.g. 'curl'
    matched_destination TEXT    NOT NULL,       -- dst_ip or hostname_or_sni value
    detection_axis      TEXT    NOT NULL        -- 'ip' or 'hostname'
                        CHECK(detection_axis IN ('ip', 'hostname')),
    occurrence_count    INTEGER NOT NULL,       -- count of FLAGs that triggered this
    window_start        REAL    NOT NULL,       -- Unix timestamp: earliest matching event
    window_end          REAL    NOT NULL,       -- Unix timestamp: latest matching event
    proposed_yaml_rule  TEXT    NOT NULL,       -- candidate policy.yaml snippet (YAML string)
    status              TEXT    NOT NULL        -- 'pending' | 'approved' | 'rejected'
                        CHECK(status IN ('pending','approved','rejected')),
    reasoning_text      TEXT    NOT NULL,       -- filled template (human-readable)
    replay_total        INTEGER NOT NULL,       -- B: total historical events matching the rule
    replay_changed      INTEGER NOT NULL,       -- A: events that would have changed verdict
    permissive_change   INTEGER NOT NULL        -- 1 if proposed rule is ALLOW-expanding, 0 otherwise
                        CHECK(permissive_change IN (0, 1))
);

-- Index for approval_cli list (filtering by status = 'pending')
CREATE INDEX IF NOT EXISTS idx_proposed_rules_status
    ON proposed_rules(status);

-- Index for ordering proposals by age
CREATE INDEX IF NOT EXISTS idx_proposed_rules_created_at
    ON proposed_rules(created_at);
