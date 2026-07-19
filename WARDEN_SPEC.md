# WARDEN — Project Context & Build Specification
### (working name: war(den).ai)

> **This is a living document.** Update it whenever architecture decisions change.
> Never delete history — append to the Changelog at the bottom instead of silently editing past decisions.
> Version: 0.1 — Initial spec, pre-Phase-1 build.

---

## 0. North Star

> **Protect against AI agents misusing their power, by acting as a fake shell.**

Two sentences. If a proposed feature can't be traced back to this, it doesn't belong in core — it belongs in a plugin, or in a "someday" list.

---

## 1. What Warden Is (Non-Technical)

Warden is a digital safety cage for AI agents that have been given control of a real computer.

When an AI agent can run terminal commands, write code, or move files, it can make catastrophic mistakes or get manipulated into doing damage. Warden sits invisibly between the agent and the operating system. If the agent tries something dangerous — deleting system files, reading credentials, exfiltrating data — Warden stops it instantly.

Instead of erroring or crashing the agent's workflow, Warden **lies**: it tells the agent "task completed successfully." The agent's loop continues uninterrupted. The real machine is untouched. The human sees exactly what was attempted, in a ledger, after the fact (or live).

---

## 2. What Warden Is NOT

- **Not an LLM making decisions.** Every verdict is deterministic, rule-based, and reproducible. No model-in-the-loop for Phase 1–2. (Phase 3 introduces an *advisory* AI loop — it proposes rule changes, it never enforces directly. See §7.)
- **Not a firewall.** A firewall blocks. Warden blocks *and* fabricates a plausible success so the agent's control loop never detects the interference.
- **Not a replacement for Docker/sandboxing.** Docker (or equivalent) is the *jail* — the room with no real doors. Warden is the *guard inside the room* who also controls what the prisoner is told. Defense in depth: if Warden fails, the jail still holds. If the jail is misconfigured, Warden still intercepts.
- **Not a monolith.** No component may require another component to change in order to add a new capability. See §4 (Modularity Contracts) — this is non-negotiable and is the single most important structural decision in this project.

---

## 3. High-Level Architecture (The Skeleton)

This shape must not change as features are added. New capabilities are new **inspectors** or new **executors**, never new branches bolted into the core loop.

```
[ Isolated AI Agent  (Docker Jail) ]
               │
               ▼  emits an Action (shell command / network call / file op / ...)
     ┌─────────────────────────┐
     │      WARDEN DAEMON       │   (headless background service, no UI)
     │                          │
     │  ┌────────────────────┐  │
     │  │  Token / Structure  │  │   parses the raw action into a structured
     │  │      Parser         │  │   representation (never string-matching)
     │  └─────────┬──────────┘  │
     │            ▼             │
     │  ┌────────────────────┐  │
     │  │  Inspector Chain    │  │   ordered list of pluggable inspectors:
     │  │  (Command / Net /   │  │   each returns allow / block / flag + reason
     │  │   File / Rate / ...)│  │
     │  └─────────┬──────────┘  │
     │            ▼             │
     │  ┌────────────────────┐  │
     │  │   Rule Engine       │  │   evaluates policy.yaml against the
     │  │  (reads policy.yaml)│  │   parsed action + inspector verdicts
     │  └─────────┬──────────┘  │
     │            ▼             │
     │  ┌────────────────────┐  │
     │  │     Executor        │  │   real execution   OR   fabricated
     │  │                     │  │   success payload generation
     │  └─────────┬──────────┘  │
     │            ▼             │
     │  ┌────────────────────┐  │
     │  │      Logger         │  │   writes one structured event per action
     │  └─────────┬──────────┘  │
     └────────────┼─────────────┘
                  ▼
       [ Shared SQLite Ledger ]
                  ▲
                  │  read-only, no write access, no control channel
        ┌─────────┴─────────┐
        │                    │
   [ CLI Viewer ]     [ Dashboard Viewer ]
```

Key property: **the Ledger is the only thing the viewers know about.** Neither CLI nor Dashboard ever talks to the agent, the daemon's internals, or the rule engine directly. This means you can delete and rewrite the entire UI layer in a weekend without risk to the security-critical path.

---

## 4. Modularity Contracts (the part that must survive forever)

Every inspector implements the same interface, regardless of what it inspects:

```
Inspector.inspect(action: ParsedAction) -> Verdict(
    decision: ALLOW | BLOCK | FLAG,
    reason: str,
    confidence: optional,
    source_inspector: str
)
```

Every executor implements:

```
Executor.run(action: ParsedAction, verdict: Verdict) -> ExecutionResult(
    real_output: optional,
    fabricated_output: optional,
    success: bool
)
```

Every logger implements:

```
Logger.record(event: LedgerEvent) -> None
```

**Rule:** the core daemon loop only ever calls these three interfaces. It never contains inspector-specific or executor-specific logic. Adding "file access inspection" or "rate-limit inspection" in the future means writing a new class that satisfies `Inspector`, registering it in a config list, and nothing else changes.

**Policy is data, not code.** `policy.yaml` defines rules (patterns, path scopes, risk tiers, actions). The Rule Engine reads it at startup (and ideally hot-reloads it). Adding a new dangerous pattern is a text edit, never a code change. This is also what makes Warden genuinely extensible by outside contributors without touching the engine.

---

## 4a. Design Principle: Structural Attack Surface Reduction

Rather than trying to make the parser/policy layer understand every possible shell trick or edge case (which is an unbounded, unwinnable list), Warden shrinks the actual attack surface structurally. For example, executing commands with `shell=False` removes a real shell from the execution path entirely, neutralizing vast classes of injection attacks by default. 

Warden then explicitly re-implements only the specific shell features actually needed for agent operation (like `cd` state tracking or `>`/`>>` output redirection) as explicit, tested, Warden-owned behavior. Future contributors should follow this principle: do not chase endless parser workarounds for edge cases; instead, remove the vulnerable capability structurally and safely emulate the minimum necessary subset.

---

## 5. Proposed Repository Structure

```
warden/
├── daemon/
│   ├── core.py                # main loop: parse → inspect → rule-eval → execute → log
│   ├── parser/
│   │   └── shell_parser.py    # tokenizes commands into structured ParsedAction
│   ├── inspectors/
│   │   ├── base.py            # Inspector interface
│   │   ├── command_inspector.py
│   │   └── network_inspector.py   # (Phase 2)
│   ├── rules/
│   │   ├── engine.py          # loads + evaluates policy.yaml
│   │   └── policy.yaml
│   ├── executors/
│   │   ├── base.py
│   │   ├── real_executor.py
│   │   └── fake_executor.py   # fabricates plausible stdout/exit codes
│   └── ledger/
│       ├── logger.py          # writes to SQLite
│       └── schema.sql
├── clients/
│   ├── cli/                   # thin, reads ledger only
│   └── dashboard/              # thin, reads ledger only (Phase 4)
├── jail/
│   └── Dockerfile             # sandboxed agent environment, read-only fs
├── tests/
└── WARDEN_SPEC.md             # this file
```

---

## 6. Phase 1 — Smart Command Deception (current focus)

### Goals
- Real structural parsing of shell commands (no substring/keyword grepping).
- Path-scoped, policy-driven verdicts (not a flat blacklist).
- Deterministic fake-success fabrication that's plausible enough an agent's control loop doesn't notice.
- Every action, verdict, and outcome logged to SQLite.

### Non-Goals (explicitly deferred)
- No network interception yet (Phase 2).
- No AI-assisted rule suggestions yet (Phase 3).
- No UI beyond raw log output / basic CLI (Phase 4).
- No multi-agent or multi-session handling yet — single agent, single session is enough to prove the mechanic.

### Component Detail

**Parser (`shell_parser.py`)**
- Use `shlex` (or a proper POSIX-shell-grammar library) to tokenize input into argv form.
- Recursively split on shell metacharacters: `;`, `&&`, `||`, `|`, and detect subshell/command substitution (`$(...)`, backticks) — each sub-command must be independently parsed and evaluated, not skipped.
- Output a `ParsedAction` with: `binary`, `args`, `flags`, `target_paths` (resolved/normalized, not raw strings), `raw_input`.

**Command Inspector**
- Consumes `ParsedAction`.
- Cross-references `binary` + `target_paths` against `policy.yaml` scopes.
- Returns a `Verdict` — does not decide fake-vs-real itself, that's the Rule Engine's job once all inspectors report in.

**Rule Engine**
- Loads `policy.yaml` at startup.
- `policy.yaml` schema (draft):
  ```yaml
  rules:
    - match:
        binary: ["rm", "dd", "shred"]
        path_scope: ["!./project/**"]   # deny outside project dir
      action: block
      risk: high
    - match:
        binary: ["cat", "less", "head"]
        path_scope: ["**/.env", "**/*.pem", "**/id_rsa*"]
      action: block
      risk: high
    - match:
        binary: ["*"]
        path_scope: ["./project/**"]
      action: allow
      risk: low
  default_action: flag   # anything not matched gets flagged, not silently allowed
  ```
- Evaluates rules top-down (or by specificity — decide and document this explicitly, it's a common source of subtle bugs in rule engines).
- Emits final decision: `ALLOW`, `BLOCK` (→ fake executor), or `FLAG` (→ log prominently, decide default behavior — likely treat as block-and-log until Phase 3 exists to auto-triage).

**Executors**
- `real_executor.py`: wraps `subprocess.run`, captures real stdout/stderr/exit code.
- `fake_executor.py`: generates a plausible fabricated result — matching exit code 0, a stdout shape appropriate to the binary (e.g. `rm` on success normally prints nothing — replicate that silence, don't over-engineer a fake message that would look suspicious to the agent).

**Ledger**
- SQLite table, minimum columns: `timestamp`, `raw_input`, `parsed_action (json)`, `verdict`, `reason`, `real_or_fake`, `output`.
- This schema is intentionally generic (not shell-specific) so Phase 2's network events can log into the *same* table/shape later.

### Phase 1 Deliverable / Demo Definition
A recorded session where:
1. An agent (or a scripted stand-in) issues a mix of safe and dangerous commands, including at least one chained/composed command (`ls; rm -rf /`) and one path-scope violation (`cat ../../.env`).
2. Dangerous ones get faked successes; safe ones execute for real.
3. The ledger shows a clean, complete record of both.

This is "the GIF that goes viral" — don't move to Phase 2 until this demo is solid and rehearsed.

### Antigravity Prompts — Phase 1

Use these sequentially. Paste the "Shared Context" block once at the start of the IDE session, then feed each step prompt as you complete the previous one.

**Shared Context (paste first, once):**
```
I'm building Warden, a security daemon that sits between an AI agent and a real
operating system. It intercepts shell commands, parses them structurally (not by
keyword matching), evaluates them against a YAML policy file, and either executes
them for real or fabricates a plausible fake success — logging every decision to
SQLite. Architecture is strictly modular: a Parser, a chain of Inspectors (each
implementing the same interface), a Rule Engine reading policy.yaml, pluggable
Executors (real/fake), and a Logger — the core loop only calls these interfaces,
never inspector- or executor-specific logic. Repository structure:
[paste §5 structure here]. We are building Phase 1 only: command interception,
no network layer, no UI, no AI-assisted rules yet.
```

**Step 1 — Parser:**
```
Implement daemon/parser/shell_parser.py. It must take a raw shell command string
and return a ParsedAction object (binary, args, flags, target_paths, raw_input).
Use shlex for tokenization. It must recursively handle shell metacharacters
(; && || |) and command substitution ($(...) and backticks), splitting them into
a list of independent ParsedAction sub-commands rather than treating the whole
string as one opaque token. Include unit tests covering at least: a simple
command, a chained command, a command with substitution, and a command with
quoted arguments containing metacharacters (which should NOT be split).
```

**Step 2 — Inspector interface + Command Inspector:**
```
Implement daemon/inspectors/base.py defining the Inspector interface: a single
method inspect(action: ParsedAction) -> Verdict, where Verdict has decision
(ALLOW/BLOCK/FLAG), reason, and source_inspector fields. Then implement
daemon/inspectors/command_inspector.py, which inspects a ParsedAction's binary
and target_paths against loaded policy rules (policy passed in, not hardcoded).
It should not load policy.yaml itself — that's the Rule Engine's job — it
receives already-parsed rules as input.
```

**Step 3 — Rule Engine + policy.yaml:**
```
Implement daemon/rules/engine.py, which loads and parses policy.yaml (schema:
[paste the yaml schema from §6 here]) into a queryable rule set, and evaluates a
ParsedAction plus any inspector Verdicts into a final decision: ALLOW, BLOCK, or
FLAG. Document and implement a clear, deterministic rule-precedence order (e.g.
most specific path_scope wins, then first-match-in-file-order as tiebreaker) and
write tests that lock in that precedence behavior explicitly, since it's the
easiest part of a rule engine to get subtly wrong.
```

**Step 4 — Executors:**
```
Implement daemon/executors/base.py, real_executor.py, and fake_executor.py.
real_executor wraps subprocess.run and returns real stdout/stderr/exit code.
fake_executor fabricates a plausible result for a blocked action — matching the
typical success behavior of that specific binary (e.g. rm prints nothing on
success; mkdir prints nothing; echo would just print its argument) rather than a
generic "success" message that would look synthetic to an agent inspecting output.
```

**Step 5 — Ledger:**
```
Implement daemon/ledger/schema.sql and daemon/ledger/logger.py. One row per
action attempt: timestamp, raw_input, parsed_action (as JSON), verdict, reason,
whether execution was real or fake, and the output returned to the agent. Keep
the schema generic enough that a future network-layer event (Phase 2) could log
into the same table without a schema migration — i.e. avoid shell-specific
column names.
```

**Step 6 — Core loop + demo:**
```
Implement daemon/core.py wiring Parser → Inspector chain → Rule Engine →
Executor → Logger into a single loop that reads a command, processes it through
every stage, and returns output to the caller exactly as a real shell would.
Then write a demo script that feeds it a sequence including a chained dangerous
command (e.g. "ls; rm -rf /"), a path-scope violation (e.g. "cat ../../.env"),
and a normal safe command, and prints the ledger contents afterward so the
full block-vs-allow-vs-fake behavior is visible end to end.
```

---

## 7. Phase 2 — The Network Guard (architecture decided, code not started)

**Goal:** catch what the shell interceptor structurally cannot see — an agent writing pure Python (`requests`, `socket`) that never touches a shell command at all.

### 7.1 Architecture Decision (finalized)

**Pattern: Sidecar container via docker-compose.**

The AI agent continues to run in the existing strictly-locked-down jail container, which remains fully unprivileged — no capabilities, no network privileges, exactly as defined in `jail/Dockerfile`. The Warden daemon's network interceptor runs in a **separate sidecar container** on the same Docker bridge network. The sidecar is granted `CAP_NET_ADMIN` specifically and exclusively — the agent's jail container never receives this capability. Defense in depth is preserved: neither container has an escape path to the other's privilege set.

Key layout:
```
  docker-compose
  ├── jail          (agent runs here)
  │     unprivileged, cap_drop: ALL, read-only fs
  │     connected to: warden_bridge
  │
  └── warden-sidecar   (network interceptor runs here)
        CAP_NET_ADMIN only
        connected to: warden_bridge
        mounts: shared volume → Ledger (write)
```

All traffic from the jail container that exits via the bridge is visible to the sidecar. The sidecar is the only thing that touches `iptables`/NFQUEUE. The jail never knows interception is happening.

---

### 7.2 Enforcement Mechanism — v1.0 (current plan)

**Python + NFQUEUE (`netfilterqueue` library).**

Rationale:
- Maintains momentum: stays in the existing Python daemon codebase, same language as the Inspector/Executor contracts.
- `netfilterqueue` gives actual packet-level enforcement (intercept-before-forward, can drop or allow packets) — not passive sniffing.
- Scapy is used for parsing the intercepted packet bytes into structured fields (destination IP, port, protocol, hostname from SNI/DNS), not for enforcement itself.
- Fastest path to a working, demoable Phase 2. Production performance is not yet a requirement.

Flow inside the sidecar:
```
  iptables rule → NFQUEUE (queue 0)
       ↓
  netfilterqueue callback
       ↓
  Scapy: parse packet bytes → (dst_ip, dst_port, protocol, sni)
       ↓
  NetworkInspector.inspect(ParsedNetworkAction) → Verdict
       ↓
  Rule Engine: evaluates against policy.yaml network rules
       ↓
  drop packet   OR   accept packet
       ↓
  Ledger: log event (same schema, event_type="network")
```

---

### 7.3 Limitation: Stateless SNI Filtering (Phase 2.5 TODO)

**RISK: hostname/SNI-based allow rules cannot fire under the current stateless first-packet default-deny model; only IP/CIDR-based rules currently function.**

In a default-deny firewall (where the default `0.0.0.0/0` rule is `BLOCK`), a stateless packet inspector evaluates every packet entirely on its own. For an HTTPS connection, the very first packet is a TCP `SYN` packet. This packet contains no payload and therefore no Server Name Indication (SNI) string.

Because `NetworkInspector` looks at this empty `SYN` packet and sees no hostname, it cannot match any hostname-based `ALLOW` rules (like `api.openai.com`). It falls through to the default `BLOCK` rule, and the packet is dropped immediately. The TCP handshake is killed before the client ever has a chance to send the TLS `ClientHello` (which contains the SNI).

**The Phase 2.5 Fix (Connection Tracking):**
To support hostname rules, the sidecar must implement stateful connection tracking (conntrack). The flow will look like this:
1. **Provisional Allow**: When a TCP `SYN` packet arrives with no payload, if there are *any* hostname rules for that port, provisionally accept it and log the connection state.
2. **Handshake Completion**: Allow the `SYN-ACK` and `ACK` to pass.
3. **SNI Inspection**: Once the `ClientHello` packet arrives, inspect the SNI.
4. **Retroactive Enforcement**: If the SNI matches an `ALLOW` rule, let the connection continue. If it doesn't match (or if the packet was non-TLS or malformed), immediately drop the packet, flush the connection state, and send a TCP `RST` to kill the connection.

*Do not implement this now. It is scheduled AFTER Phases 1-4 are complete, not immediately following Phase 2 — it's a hardening pass, not a blocker.*

---

### 7.4 The Correlation Gap (and the Two-Ledgers Gap)

#### Background: Two Gaps, Not One

When this section was first written, the problem was framed as a single correlation gap: the daemon and sidecar have no shared action/session ID linking a shell event to a network event. Investigation during Phase 3 preparation revealed a second, independent gap sitting underneath it: **the daemon and sidecar have never written to the same SQLite file at all.**

The original Phase 2 design intent ("network events log into the existing Ledger schema — no schema migration required") was only partially achieved. The *schema* is shared — both sides use the same `events` table structure. But the *files* are separate:

- The **daemon** writes shell events to `warden_demo.db` directly on the host filesystem.
- The **sidecar** writes network events to `/data/ledger/warden.db` inside the `warden_ledger` Docker volume.

These two files have never been mounted in the same place at the same time. The daemon has no access to `warden_ledger`; the sidecar has no access to the host-side `warden_demo.db`. Correlation via ledger JOIN has therefore never been possible — not just unlabeled, but physically impossible across two separate files.

#### Why This Matters for Phase 3

Phase 3's advisor needs to trace network outcomes back to the shell commands that caused them. Without this, it can only analyze shell events or network events in isolation — it cannot answer "this binary consistently makes network calls to this class of IP" as a compound pattern, which is the core of what makes Phase 3 useful. The two-ledgers gap must be closed as a prerequisite to Phase 3, independent of the correlation fix below.

#### Approaches Investigated (with Outcomes)

**RULED OUT — Environment variable tagging via `/proc/<pid>/environ`:**

The original recommended approach: when the daemon dispatches a command, set `WARDEN_ACTION_ID=<uuid>` as an env var on the subprocess; the sidecar reads `/proc/<pid>/environ` of the originating process to extract the ID. Tested directly against the live stack. Result: not viable. The jail and sidecar are in separate PID namespaces. The sidecar's `/proc` filesystem only exposes its own processes — jail PIDs simply do not appear there at all (`No such file or directory`). No capability grant fixes this; separate PID namespaces are a hard boundary regardless of `CAP_NET_ADMIN` or `CAP_SYS_PTRACE`.

**RULED OUT — PID-based correlation:**

The daemon logs the PID of the real subprocess; the sidecar looks up which PID owns a given TCP connection via conntrack metadata, then joins on PID + timestamp. Ruled out for the same reason: the sidecar cannot see jail PIDs in its `/proc`. PID ownership lookup requires visibility into the PID namespace of the process owning the socket — which the sidecar does not have.

**FALLBACK ONLY — Timestamp-window correlation:**

Heuristically matching shell events to network events by overlapping time windows. Used manually during the validation milestone. Fragile (breaks when multiple things happen concurrently), requires querying two separate files, and offers no causal precision. Acceptable only as a temporary stopgap before the fix below is implemented.

#### RECOMMENDED FIX — Shared-Volume `pending_actions` + Ledger Unification

This is a compound fix addressing both gaps simultaneously. It requires no cross-namespace process visibility; everything operates through the `warden_ledger` Docker volume that the sidecar already has full read-write access to.

**Part 1 — `pending_actions` table (solves correlation):**

When the daemon dispatches a command for real execution, it writes one row to a `pending_actions` table in the shared volume's SQLite file immediately before `subprocess.Popen` returns:

```sql
CREATE TABLE pending_actions (
    action_id    TEXT PRIMARY KEY,
    dispatched_at REAL NOT NULL,   -- unix timestamp, millisecond precision
    binary       TEXT,
    args         TEXT,             -- JSON-serialized argv
    pid          INTEGER,          -- subprocess PID, set after Popen returns
    expires_at   REAL NOT NULL     -- dispatched_at + TTL (e.g. 60s)
);
```

When the sidecar intercepts a packet, it queries `pending_actions` for rows where `dispatched_at` is within ±N seconds of the packet timestamp and `expires_at` has not passed. The sidecar tags the network event it writes with the matched `action_id`. Both sides GC expired rows at write time. This is sub-second timestamp matching between two cooperating processes on the same file — a completely different reliability class from cross-file human eyeballing.

**Part 2 — Ledger unification (solves the two-ledgers gap):**

Route the daemon's main shell event writes to the shared `warden_ledger` volume instead of the host-side `warden_demo.db`. This gives Phase 3 a single SQLite file containing all events (shell and network), linked by `action_id`, queryable with a plain JOIN. This is the original Phase 2 design intent, finally realized.

These two parts should be implemented together — the daemon already needs a write path to the shared volume for `pending_actions`, so routing its main ledger writes there is a small incremental step with high Phase 3 payoff.

*Open question: confirm whether the daemon running on the host can reliably write to `warden_ledger` (a Docker-managed named volume) without going through docker-compose — or whether the cleanest path is to move daemon execution inside a container with the volume mounted. Do not resolve this now; it is a sequencing decision for when Phase 3 component work begins.*

#### Implementation Breakdown — Compound Fix

This subsection contains the component-level detail and sequenced Antigravity prompts for building the compound fix. **Do not execute any of these steps until this plan is approved.**

##### Volume Access: How the Daemon Gets a Write Path to `warden_ledger`

The daemon currently runs on the **host** and writes to `warden_demo.db` in the project root — a plain host-filesystem path. The `warden_ledger` Docker volume is managed by Docker and lives at `/var/lib/docker/volumes/warden_warden_ledger/_data` on the Linux VM inside Docker Desktop — it is **not directly accessible as a host path on macOS**.

Resolution: mount the `warden_ledger` volume into the `warden-sidecar` container (already done) **and** additionally mount it into a new optional `warden-daemon` service in `docker-compose.yml`, or alternatively expose the volume's Linux-VM path to the host daemon via an explicit volume bind. The recommended path: **add a `WARDEN_LEDGER_PATH` environment variable to the daemon's startup** (mirroring how the sidecar already uses `WARDEN_LEDGER_PATH=/data/ledger/warden.db`). The demo scripts that instantiate `WardenDaemon` pass this path explicitly. In development (host-only, no Docker), the daemon continues writing to the local `warden_demo.db` as before. When running in the full docker-compose stack, it receives a path inside the mounted volume.

*Open question resolved here: the daemon does NOT need to move into a container. The `warden_ledger` volume can be bind-mounted to a known host-accessible directory (e.g. `./ledger_data:/data/ledger:rw` added to docker-compose.yml as a second mount point), making it reachable by both the host-side daemon and the sidecar container under the same content path.*

##### Component Breakdown

**`daemon/ledger/schema.sql` [MODIFY]**

Add the `pending_actions` table. Because the schema already uses `CREATE TABLE IF NOT EXISTS`, adding the new table to `schema.sql` is safe and non-destructive — `Logger._initialise()` calls `executescript(schema_sql)` on startup, which will create the new table if it doesn't exist and leave existing `events` rows completely untouched. No migration strategy, no version bump required. Historical data in `warden_demo.db` is unaffected; the new table simply doesn't exist there until the daemon next opens it.

```sql
CREATE TABLE IF NOT EXISTS pending_actions (
    action_id     TEXT PRIMARY KEY,
    dispatched_at REAL NOT NULL,   -- Unix timestamp, float, millisecond precision
    binary        TEXT NOT NULL,
    args          TEXT NOT NULL,   -- JSON-serialized list
    pid           INTEGER,         -- Set after Popen returns; NULL if cd (no subprocess)
    expires_at    REAL NOT NULL    -- dispatched_at + TTL_SECONDS (e.g. 60.0)
);

CREATE INDEX IF NOT EXISTS idx_pending_actions_dispatched
    ON pending_actions(dispatched_at);
```

**`daemon/ledger/logger.py` [MODIFY]**

Add four new methods to `Logger`:

- `write_pending_action(action_id, dispatched_at, binary, args, pid=None, ttl=60.0)` — inserts a row into `pending_actions`. Called by `core.py` at the moment of real dispatch.
- `update_pending_action_pid(action_id, pid)` — `UPDATE pending_actions SET pid=? WHERE action_id=?`. Called by `core.py` after `Popen` returns the PID. Separate from `write_pending_action` because the PID is only available after the process has started.
- `resolve_pending_action(packet_timestamp, window_seconds=5.0)` — queries `pending_actions` for the best matching row within `±window_seconds` of `packet_timestamp`, filters `expires_at > now`, returns the `action_id` or `None`. Called by `sidecar/interceptor.py`.
- `cleanup_pending_actions()` — deletes all rows where `expires_at < now`. Called by `interceptor.py` on every packet arrival as a cheap GC step (SQLite `DELETE WHERE` is fast on a small, indexed table).

No changes to `Logger.record()`, `LedgerEvent`, or the `events` table itself.

**Concurrency — WAL mode with two writers on the same file:**

SQLite WAL mode supports **multiple concurrent readers and one writer at a time**. When a second writer tries to write while one is active, it waits on a short write-lock (default 5 seconds before returning `SQLITE_BUSY`). The daemon and sidecar will interleave writes infrequently (one daemon write per real dispatch, one sidecar write per intercepted packet), and their write windows are short (a single `INSERT` or `DELETE`). This is well within WAL mode's design envelope. Both processes access the file through the same underlying path (the Docker volume), so there are no two-mount-context coherency issues — it is one file on one Linux filesystem, seen through one kernel. The daemon must open the connection with `timeout=5` (SQLite's busy timeout) to handle the rare case of simultaneous writes gracefully.

**`daemon/core.py` [MODIFY]**

In `_process_single()`, at Stage 4 (Execute), the dispatch point splits for real vs. fake:
- For `Decision.ALLOW` (real execution path), immediately before calling `executor.run()`: generate `action_id = str(uuid.uuid4())`, call `self._logger.write_pending_action(...)` with `pid=None` initially.
- After `executor.run()` returns: if the executor exposes a `pid` (RealExecutor will need to surface the subprocess PID through `ExecutionResult`), call a second `logger.update_pending_action_pid(action_id, pid)`. *This is a nice-to-have for debugging; the core correlation works on timestamp alone if PID is not populated.*
- For `Decision.BLOCK`/`FLAG` (fake execution): no `pending_actions` write — fabricated commands never make real network calls.
- The `action_id` is also stored in `LedgerEvent` as part of the shell event row so the JOIN works: add `action_id TEXT` column to the `events` table (NULL for network events that couldn't be correlated, and for all pre-fix historical rows).

**`daemon/executors/real_executor.py` [MODIFY — minimal]**

Surface the subprocess PID in `ExecutionResult` so `core.py` can update the `pending_actions` row. `subprocess.run()` does not expose PID after completion; switch to `subprocess.Popen` + `.communicate()` to get `.pid` before waiting. `ExecutionResult` gains an optional `pid: Optional[int] = None` field. The existing timeout/capture behavior is preserved.

**`sidecar/interceptor.py` [MODIFY]**

In `packet_callback`, after step 3 (Evaluate) and before step 4 (Log):
- Call `logger.cleanup_pending_actions()` — cheap, runs on every packet.
- Call `action_id = logger.resolve_pending_action(packet_timestamp)` where `packet_timestamp` is `time.time()` at the moment the packet arrives.
- Pass `action_id` (may be `None`) into `LedgerEvent` via a new optional field.

`LedgerEvent` gains `action_id: Optional[str] = None`. The `events` INSERT in `logger._write()` includes it.

**`docker-compose.yml` [MODIFY]**

Add a bind-mount that makes the `warden_ledger` volume accessible at a known host path (e.g. `./ledger_data`), so the host-side daemon can write to it:

```yaml
volumes:
  warden_ledger:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: ./ledger_data   # host directory, created on first docker-compose up
```

Or simpler: add `- ./ledger_data:/data/ledger:rw` as a bind-mount alongside the named volume in both the sidecar and any new daemon container. The daemon startup script passes `ledger_path=Path("./ledger_data/warden.db")` when running in full-stack mode.

##### Testing Plan

A passing compound fix requires all of the following to be demonstrated:

1. **`pending_actions` row written on real dispatch:** run `daemon.process("ls ./project")` (ALLOW-scoped), then query `pending_actions` — exactly one row exists with the correct `binary`, `dispatched_at`, and a non-null `pid`.
2. **No `pending_actions` row on fake dispatch:** run `daemon.process("rm -rf /")` (BLOCK-scoped), confirm no row in `pending_actions`.
3. **Network event gets tagged:** with the daemon and sidecar running together, dispatch a real command that makes a network call (e.g. `python3 -c "import urllib.request; urllib.request.urlopen('https://google.com')"`) — ALLOW at the shell level, BLOCK at the network level. The resulting network event row in `events` must have a non-null `action_id` matching the shell event's `action_id`.
4. **JOIN query returns coherent result:** a single SQL query joining `events` on `action_id` returns one shell event row and one (or more, for retries) network event rows for the same dispatch. No cross-join pollution from other concurrent actions.
5. **Historical data unaffected:** all pre-fix rows in the `events` table survive `Logger._initialise()` being called on the same database (i.e., `CREATE TABLE IF NOT EXISTS` doesn't truncate); their `action_id` column is NULL, which is acceptable.
6. **WAL concurrency holds:** run the daemon and sidecar simultaneously for 60 seconds with a rapid-fire loop of real dispatches; confirm no `SQLITE_BUSY` errors logged to stderr on either side.

##### Antigravity Prompts — Compound Fix

Use these sequentially. Paste the Shared Context block once at the start of the session.

**Shared Context (paste first, once):**
```
I'm building Warden. The compound fix I'm implementing adds a `pending_actions`
table to the shared SQLite ledger so the network sidecar can correlate intercepted
packets back to the specific shell command that caused them (action_id), and routes
the daemon's main event writes to the same Docker-managed `warden_ledger` volume
used by the sidecar. Current state: daemon writes to warden_demo.db on the host;
sidecar writes to /data/ledger/warden.db in the warden_ledger Docker volume —
they have never shared one file.

Key files:
- daemon/ledger/schema.sql — existing events table (CREATE TABLE IF NOT EXISTS, safe to add new tables)
- daemon/ledger/logger.py — Logger class, _initialise() runs schema.sql at startup
- daemon/core.py — _process_single() is where dispatch happens (Stage 4)
- daemon/executors/real_executor.py — uses subprocess.run(); needs PID surfaced
- sidecar/interceptor.py — packet_callback() is where network events are logged
- docker-compose.yml — warden_ledger is a named Docker volume, sidecar mounts it at /data/ledger

Constraints: shell=False everywhere, WAL mode already enabled, never raises in
Logger.record(), LedgerEvent is a dataclass that maps 1-to-1 to an events row.
```

**Step 1 — Schema:**
```
Add the `pending_actions` table to daemon/ledger/schema.sql. It needs:
action_id (TEXT PRIMARY KEY), dispatched_at (REAL, unix float, ms precision),
binary (TEXT NOT NULL), args (TEXT NOT NULL, JSON list), pid (INTEGER, nullable),
expires_at (REAL NOT NULL). Add a dispatched_at index. Also add an action_id TEXT
nullable column to the existing events table (ALTER TABLE events ADD COLUMN if it
doesn't exist, or add it to the CREATE TABLE IF NOT EXISTS — note: IF NOT EXISTS
won't add new columns to an already-created table, so this needs an ALTER TABLE
migration guard in Logger._initialise()). Write a test confirming: (a) calling
_initialise() twice on the same DB does not error; (b) pending_actions table is
created; (c) events table has an action_id column.
```

**Step 2 — Logger methods:**
```
Add three methods to Logger in daemon/ledger/logger.py:
1. write_pending_action(action_id, dispatched_at, binary, args, pid=None, ttl=60.0)
   — inserts into pending_actions; expires_at = dispatched_at + ttl.
2. update_pending_action_pid(action_id, pid) — UPDATE pending_actions SET pid=?
   WHERE action_id=?. Separate from write because PID is only available after
   Popen returns.
3. resolve_pending_action(packet_timestamp, window_seconds=5.0) -> Optional[str]
   — SELECT action_id FROM pending_actions WHERE dispatched_at BETWEEN
   (packet_timestamp - window_seconds) AND (packet_timestamp + window_seconds)
   AND expires_at > now ORDER BY ABS(dispatched_at - packet_timestamp) ASC LIMIT 1.
   Returns action_id or None.
4. cleanup_pending_actions() — DELETE FROM pending_actions WHERE expires_at < now.
All under self._lock. Never raises. Write unit tests for each covering: hit, miss,
expiry, and concurrent write (open two Logger instances on the same file and call
write + resolve simultaneously).
```

**Step 3 — RealExecutor PID surfacing:**
```
In daemon/executors/real_executor.py, switch from subprocess.run() to
subprocess.Popen() + .communicate() so the subprocess PID is available before
waiting for completion. Add pid: Optional[int] = None to ExecutionResult in
daemon/executors/base.py. RealExecutor.run() sets result.pid = proc.pid.
Preserve all existing timeout behavior (use Popen.communicate(timeout=30), catch
TimeoutExpired, call proc.kill() + proc.communicate() on timeout).
Confirm existing tests still pass — no behavior change, only PID surfacing.
```

**Step 4 — core.py dispatch integration:**
```
In daemon/core.py _process_single(), at Stage 4 for ALLOW decisions (non-cd path):
1. Before executor.run(): action_id = str(uuid.uuid4()); call
   self._logger.write_pending_action(action_id, time.time(), action.binary,
   json.dumps(action.args)).
2. After executor.run(): if execution_result.pid: call
   self._logger.update_pending_action_pid(action_id, execution_result.pid).
3. Pass action_id to LedgerEvent (add action_id field to LedgerEvent dataclass
   and to the events INSERT in logger._write()). For non-ALLOW paths, action_id=None.
Write a test: dispatch an ALLOW command, query pending_actions, assert the row
exists with correct fields. Dispatch a BLOCK command, assert no row in pending_actions.
```

**Step 5 — interceptor.py correlation:**
```
In sidecar/interceptor.py packet_callback(), between step 3 (Evaluate) and step 4
(Log):
1. import time at the top of the file.
2. packet_ts = time.time() immediately on packet arrival (before parse).
3. After evaluate: logger.cleanup_pending_actions(); action_id =
   logger.resolve_pending_action(packet_ts).
4. Pass action_id to LedgerEvent (action_id=action_id or None).
Write a test using a MockLogger that records write_pending_action and
resolve_pending_action calls, confirming: (a) cleanup is called on every packet;
(b) action_id from resolve is passed into LedgerEvent; (c) None is handled
gracefully (no crash, network event still logged with action_id=null).
```

**Step 6 — Volume access + end-to-end verification:**
```
Update docker-compose.yml to make the warden_ledger volume accessible at a
known host path (./ledger_data) so the host-side daemon can write to it.
Update demo/run_agent_test.py (and any other daemon startup scripts) to accept
a WARDEN_LEDGER_PATH environment variable and pass it as ledger_path to
WardenDaemon — defaulting to ./warden_demo.db if unset (preserves existing
behaviour). Then run the full end-to-end test: docker-compose up, dispatch one
real ALLOW command that makes a network call (use the existing run_agent_test.py
pattern), then run this verification query against the shared ledger:
  SELECT s.id, s.raw_input, s.verdict, n.raw_input, n.verdict, s.action_id
  FROM events s JOIN events n ON s.action_id = n.action_id
  WHERE s.event_type='shell_command' AND n.event_type='network'
  ORDER BY s.id;
Assert: at least one row returned with matching action_id, correct verdicts
(ALLOW for shell, BLOCK for network). All existing pytest tests must still pass.
```

---

### 7.5 Enforcement Mechanism — v2.0 (explicitly deferred, not started)

**Rust + eBPF/XDP.**

This migration is planned but deliberately not started until Phases 1–4 are otherwise complete. Rationale for deferral: the Python + NFQUEUE v1.0 path reaches a working demo fastest, and the modular Inspector/Executor contracts are designed to absorb the code migration cleanly — a new `NetworkInspector` implementation in Rust satisfying the same interface replaces the Python one without touching the core loop.

**Important:** this migration is not just a code swap. eBPF has materially different privilege and kernel requirements from NFQUEUE userspace queuing:
- eBPF programs require `CAP_BPF` (or `CAP_SYS_ADMIN` on older kernels), not `CAP_NET_ADMIN`.
- XDP attaches at the driver level, before the kernel networking stack — different attachment point than NFQUEUE.
- The docker-compose sidecar definition, the kernel version requirements, and the container security model will all need real rework, not just a code replacement.

**Sourcing Approach:** Rather than writing eBPF from scratch, the recommended approach is to start from a known-working example (e.g. from Aya's own example repository, matching the already-chosen framework) and get it running unmodified first, before adapting it to Warden's specific needs (packet parsing, NetworkInspector integration, etc.). Note that eBPF's verifier rejects code based on static safety properties regardless of whether it was written by a human or an AI agent — expect a real iterate-against-verifier-errors loop as a normal part of this work, not a sign of a flawed approach.

Do not design the v1.0 NFQUEUE sidecar as if it will "just be swapped" for eBPF later — flag the orchestration differences explicitly when the migration is eventually scoped. The Inspector/Executor contract absorbs the code cleanly; the container/infra layer does not absorb it automatically.

---

### 7.6 Component Breakdown

**`docker-compose.yml` (new file, project root)**
- Defines two services: `jail` (existing container) and `warden-sidecar` (new).
- `jail` service: `cap_drop: ALL`, `security_opt: no-new-privileges`, `read_only: true`, `tmpfs: [/tmp]`. Connects to `warden_bridge` network.
- `warden-sidecar` service: built from a new `sidecar/Dockerfile`. `cap_add: [NET_ADMIN]`, `cap_drop: ALL` first (so only NET_ADMIN is granted). Mounts the shared Ledger volume (write access). Uses `network_mode: "service:jail"` to securely share the jail's network namespace (which implicitly connects it to `warden_bridge`).
- Shared volume: `warden_ledger` — bind-mounted into the sidecar at the ledger path, read-only-mounted by any future viewer containers.
- Bridge network: `warden_bridge` — internal, no external routing unless explicitly allowed.

**`sidecar/Dockerfile` (new file)**
- Based on `python:3.11-slim`.
- Installs: `netfilterqueue` (NFQUEUE Python bindings), `scapy`, `iptables` (in-container).
- Entrypoint: `python3 sidecar/interceptor.py`.
- Note: `netfilterqueue` requires the Linux kernel's `nfnetlink_queue` module — document this explicitly; it works inside Docker Desktop's Linux VM on macOS but must be verified.

**`sidecar/interceptor.py` (new file)**
- Sets up an `iptables` rule at startup on the `OUTPUT` chain: `iptables -I OUTPUT -j NFQUEUE --queue-num 0` (`OUTPUT` is used instead of `FORWARD` because the sidecar shares the jail's network namespace, meaning outbound packets from the jail originate locally).
- Binds a `netfilterqueue` queue and runs the callback loop.
- Callback: receives raw packet bytes → passes to `PacketParser` → calls `NetworkInspector` → calls `RuleEngine` → calls `LedgerLogger` → calls `packet.accept()` or `packet.drop()`.
- Cleans up `iptables` rule on exit (use `atexit` or try/finally).

**`daemon/parser/packet_parser.py` (new file)**
- Analogous to `shell_parser.py` but for packets.
- Input: raw packet bytes from the NFQUEUE callback.
- Uses Scapy to parse IP/TCP/UDP layers.
- For TCP port 443: extract TLS SNI from ClientHello if present (enables hostname-level policy rather than pure IP-based policy — significant for usability).
- For UDP port 53: parse DNS query name.
- Output: `ParsedNetworkAction(dst_ip, dst_port, protocol, hostname_or_sni, raw_bytes, direction)`.
- `direction` field: `outbound` (from jail, sourced from jail IP) vs `inbound` — enforcement only applies to `outbound` in Phase 2.

**`daemon/inspectors/network_inspector.py` (new file)**
- Implements the same `Inspector` interface as `CommandInspector`: `inspect(action: ParsedAction) -> Verdict`.
- `ParsedNetworkAction` is a subclass or variant of `ParsedAction` — it must satisfy the same interface so the Inspector chain contract holds.
- Checks `dst_ip` and `hostname_or_sni` against network rules in `policy.yaml` (see below).
- Returns `Verdict(decision, reason, source_inspector="NetworkInspector")`.

**`policy.yaml` — network rules extension**
```yaml
network_rules:
  - match:
      dst_ip: ["0.0.0.0/0"]       # any IP
      dst_port: ["*"]              # any port
    action: block
    risk: high
    reason: "default-deny all outbound"
  - match:
      hostname: ["*.openai.com", "api.anthropic.com"]   # example allowlist
      dst_port: ["443"]
    action: allow
    risk: low
```
Default policy for Phase 2 demo: **block all outbound traffic except an explicit allowlist.** This is the demonstrably more useful default — a fully isolated agent with surgical egress holes is the compelling story, not an agent with a "flag suspicious destinations" overlay.

**Ledger integration**
- Network events log into the existing `events` table (same schema), with `event_type = "network"` discriminator.
- `parsed_action` JSON blob for network events: `{"dst_ip": ..., "dst_port": ..., "protocol": ..., "hostname": ..., "direction": ...}`.
- No schema migration required — this was designed in from Phase 1 (`event_type` discriminator + JSON blob).
- The sidecar writes directly to the SQLite file via the shared volume. WAL mode (already enabled) handles concurrent writes.

---

### 7.7 Phase 2 Deliverable / Demo Definition

A recorded session where:
1. The `docker-compose up` command brings up both containers.
2. An agent (or scripted stand-in) inside the jail makes several outbound network calls: one to an allowlisted host (succeeds), several to blocked destinations (dropped at packet level).
3. The agent receives connection errors for blocked traffic (no fabricated success at the network layer in Phase 2 — the packet is dropped, the agent sees a network timeout or connection refused; fabricated network responses are Phase 3+ territory).
4. The ledger shows clean network event rows alongside the existing command event rows, with `event_type="network"`, verdict, and destination logged.

---

### 7.8 Antigravity Prompts — Phase 2

Use these sequentially after Phase 1's jail container is verified. Paste the "Shared Context" block once at the start of the session, then feed each step prompt as the previous one is complete. **Do not execute any of these yet.**

**Shared Context (paste first, once):**
```
I'm building Warden, a security daemon that intercepts AI agent actions. Phase 1
(command interception) is complete — Parser, Inspector chain, Rule Engine, Executors,
Ledger, and Core loop all exist and have passing tests. We are now building Phase 2:
network interception via a sidecar container pattern.

Architecture: The AI agent runs in an existing unprivileged Docker jail container
(jail/Dockerfile). A new sidecar container is granted CAP_NET_ADMIN only, sits on the
same Docker bridge network, and intercepts outbound packets via NFQUEUE (netfilterqueue
Python library) before they leave the network. Scapy is used only for packet parsing,
not enforcement. Network events log into the existing SQLite Ledger (same schema,
event_type="network"). The NetworkInspector implements the same Inspector interface as
CommandInspector (same inspect() -> Verdict contract). We are NOT building the eBPF/Rust
v2.0 path yet — that is explicitly deferred. Repository structure: [paste §5 structure].
```

**Step 1 — docker-compose.yml + sidecar/Dockerfile:**
```
Create docker-compose.yml at the project root and sidecar/Dockerfile. The compose file
defines two services: `jail` (the existing agent container from jail/Dockerfile) and
`warden-sidecar` (new). The jail service must have cap_drop: ALL, read_only: true,
tmpfs: [/tmp], and no cap_add — its security profile is unchanged from Phase 1.
The warden-sidecar service must have cap_drop: ALL first, then cap_add: [NET_ADMIN]
(and only NET_ADMIN). Both connect to an internal bridge network named `warden_bridge`.
A named volume `warden_ledger` is shared between them: mounted read-write into the sidecar
(at the ledger path), and read-only in the jail (if the jail needs ledger access at all —
consider carefully whether it does). sidecar/Dockerfile: based on python:3.11-slim,
installs netfilterqueue, scapy, and iptables. Entrypoint: sidecar/interceptor.py
(file not yet created). Walk me through what each directive in the compose file does
before generating it — I'm not familiar with docker-compose syntax yet.
```

**Step 2 — PacketParser (`daemon/parser/packet_parser.py`):**
```
Implement daemon/parser/packet_parser.py. It must take raw packet bytes (from a
netfilterqueue callback) and return a ParsedNetworkAction object. ParsedNetworkAction
must be a subtype of ParsedAction (so it satisfies the Inspector interface contract).
Fields: dst_ip (str), dst_port (int), protocol ("TCP"/"UDP"/"OTHER"), hostname_or_sni
(Optional[str] — extracted from TLS ClientHello SNI for port 443, DNS query name for
port 53), raw_bytes (bytes), direction ("outbound"|"inbound"). Use Scapy for parsing:
from scapy.all import IP, TCP, UDP. For SNI extraction, parse the TLS ClientHello
manually from the TCP payload (don't rely on Scapy's TLS layer — it requires additional
binding and is fragile across versions). Include unit tests using synthetic packet bytes
(construct test packets with Scapy in the test file, call bytes() on them) covering: a
plain TCP packet, a UDP DNS query, and a packet that looks like a TLS ClientHello with
a valid SNI field.
```

**Step 3 — NetworkInspector (`daemon/inspectors/network_inspector.py`):**
```
Implement daemon/inspectors/network_inspector.py. It must implement the Inspector
interface (same inspect(action: ParsedAction) -> Verdict contract as CommandInspector).
It reads network_rules from policy.yaml (these are passed in at construction, not loaded
by the inspector itself — same pattern as CommandInspector). It evaluates ParsedNetworkAction
fields (dst_ip, dst_port, hostname_or_sni) against the network rules. Rule matching:
  - hostname matching: exact match and wildcard prefix (*.domain.com matches
    sub.domain.com but not domain.com itself).
  - IP matching: support CIDR notation (use Python's ipaddress module, not string comparison).
  - Port matching: integer or "*" wildcard.
Default-deny: if no rule matches, return BLOCK (not ALLOW and not FLAG — outbound default
in Phase 2 is block-all unless explicitly allowlisted). Add the network_rules section to
policy.yaml with at least two entries: a default-deny catch-all and an example allowlist
entry. Include unit tests covering: allowlisted host allowed, blocked IP blocked, CIDR
block matching, wildcard hostname matching, default-deny fires when no rule matches.
```

**Step 4 — Ledger integration + event_type="network" rows:**
```
Verify and document that the existing Ledger schema (daemon/ledger/schema.sql,
daemon/ledger/logger.py) handles network events without any schema migration. Network
events use event_type="network" and store the ParsedNetworkAction fields as a JSON blob
in the existing parsed_action column. Write an integration test that logs a synthetic
network Verdict+ParsedNetworkAction to the Ledger and reads it back, confirming the
event_type discriminator is present and the JSON blob is correctly round-tripped. If
any schema or logger changes are required (they should be minimal or zero), make the
smallest possible change and document exactly why it was necessary.
```

**Step 5 — Sidecar interceptor (`sidecar/interceptor.py`):**
```
Implement sidecar/interceptor.py. At startup: insert an iptables rule to redirect
outbound traffic from the jail container's network interface into NFQUEUE queue 0
(determine the correct iptables chain — FORWARD or OUTPUT — based on how docker-compose
routes traffic between containers on the bridge network; document the choice and why).
Bind a netfilterqueue.NetfilterQueue to queue 0. The per-packet callback must:
  1. Call PacketParser.parse(raw_bytes) → ParsedNetworkAction.
  2. Call NetworkInspector.inspect(parsed_action) → Verdict.
  3. Call RuleEngine.evaluate([verdict]) → final decision.
  4. Call LedgerLogger.record(event) → None.
  5. Call packet.accept() if ALLOW, packet.drop() if BLOCK or FLAG.
On exit (atexit or try/finally): remove the iptables rule. Start the queue loop
(nfqueue.run()). Include a --dry-run flag that skips the iptables setup and instead
reads synthetic packet bytes from stdin, processes them through steps 1–4, and prints
the verdict — this makes local testing possible without a running Docker environment.
```

**Step 6 — End-to-end demo + docker-compose up:**
```
Write a Phase 2 demo script (demo/run_phase2_demo.py or a shell script) that:
  1. Runs docker-compose up -d to bring both containers up.
  2. Executes a series of commands inside the jail container (via docker-compose exec
     jail ...) that make outbound network calls: one to an allowlisted host, several
     to blocked hosts.
  3. Waits briefly, then queries the Ledger and prints a table showing all network
     events with their verdict, destination, and whether the packet was dropped.
  4. Runs docker-compose down.
Explain each docker-compose exec and docker-compose log command as you add it —
I want to understand what each does, not just have a working black box. The demo
must show at minimum: one ALLOW row (allowlisted host), two BLOCK rows (non-allowlisted
hosts), all in the same Ledger table as Phase 1 command events.
```

---

## 8. Validation Milestone — Real Agent Test (not started)

**Goal:** Wire a single real LLM (via API) into Warden's existing Phase 1/2 entry points using a minimal custom script, purely to validate the system against unscripted behavior and produce real ledger data for Phase 3 to read.

This is a **ONE-OFF, throwaway test**. It is explicitly NOT the same as Phase 5's general integration layer. The harness built here is not meant to be reused or productized. It is just a quick script to generate authentic, multi-turn adversarial or benign interactions for the smart policy loop to analyze.

---

## 9. Phase 3 — The Smart Policy Loop (future, not started)

**Goal:** An offline analysis process reads the Ledger, looks for patterns across attempted actions (not single-command judgments — a single `curl` isn't suspicious, twenty variations of it in ten minutes is), and *proposes* new rules for the policy. The human explicitly approves or rejects them. The advisory system never has write access to the enforced policy directly.

### Core Design Decisions

1. **No Local LLM Required:** The core detection work (spotting patterns in the ledger, such as frequency counts, clustering, threshold-crossing, or a small decision tree) must use a simple, deterministic statistical method. Using an LLM for detection would reintroduce the opacity problem the rest of Warden deliberately avoids. A decision tree or frequency threshold can be inspected directly ("this fired because frequency > threshold"). This extends the "not an LLM making decisions" principle from the enforcement path to the advisory path as well.
2. **Template-Based Explanations:** Explanations for proposed rules are templated, not LLM-generated. Because detection relies on structured data (exact counts, thresholds, matched fields), the "reasoning" for any proposal is generated by filling in a template with real numbers (e.g., "Pattern detected: N occurrences of X over timeframe Y (threshold: Z). Proposed rule: `<rule>`. Historical replay: would have changed A of B matching events."). This guarantees full auditability, as every number traces back to a ledger query, eliminating the risk of a model inventing plausible but incorrect justifications. *(Open question: if genuinely complex multi-factor patterns arise later where templating feels insufficient, revisit whether a short natural-language summary step is worth adding — but do not build this speculatively.)*
3. **Three-Tier Rule Staging System:**
   - **Tier 1 (policy.yaml):** The permanent, enforced ruleset. Only ever edited by a human, directly or via explicit approval.
   - **Tier 2 (Proposed Rules Staging):** A staging file where the advisory system writes candidate rules with their template-generated reasoning attached. Nothing here is enforced. *(Open question: format and location of this file).*
   - **Tier 3 (Dry-Run Testing):** Before any proposed rule is approved into `policy.yaml`, it must be replayed against HISTORICAL ledger data, producing a concrete "here's what would have changed" report (counts of affected ALLOW/BLOCK/FLAG events). Approval is based on this concrete evidence, not just the proposal's text.
4. **Asymmetric Scrutiny:** Proposals that make policy MORE RESTRICTIVE (e.g. FLAG → BLOCK) can go through lightweight approval. Proposals that make policy MORE PERMISSIVE (e.g. adding a new ALLOW) must require deliberately harder, more explicit confirmation, since that is the direction from which real harm would come. This asymmetry must be a structural part of the approval flow, not just an informal norm.
5. **FLAG-Only ML Inspector (Scoped Idea):** A lighter-weight, non-enforcing companion that could precede the full advisory loop. This would be an inspector that can *only* ever return `FLAG` (never `BLOCK` or `ALLOW`), adding an extra "something looks off" signal to the ledger without any risk of it making an enforcement decision. *(Do not design its implementation now; keep as a scoped backlog idea).*

---

## 10. Phase 4 — The Minimalist UI (future, not started)

Confirmed aesthetic direction (already decided, not up for relitigation later):
- Dark background, monospace font throughout — this is a terminal-adjacent tool, it should look like one.
- No generic "security dashboard" tropes: no gradient cards, no shadows, no traffic-light-everywhere iconography.
- Two-column core view: **ALLOWED** vs **INTERCEPTED**, real-time or near-real-time.
- Color used only for status, sparingly — green for allowed, red for blocked, and one neutral third color for flagged/uncertain.
- Both a terminal-UI (e.g. `textual` in Python or `ratatui` in Rust) and a minimal browser dashboard are options — pick one to build first based on which client (CLI vs web) gets used more once Phase 1 is in daily use; don't build both speculatively.

Both viewers are strictly read-only clients of the Ledger, per §3 — never allowed to develop write access or a control channel to the daemon.

---

## 11. Phase 5 — Agent Integration Layer (future, not started)

**Goal:** A general, reusable mechanism for any end user to plug an arbitrary AI agent (their own framework, tool-calling setup, etc.) into Warden's jail with minimal effort.

This is distinct from the Docker jail itself (which is already built and just an environment) and distinct from any one-off test scripts (like the Validation Milestone). This is the reusable "door" into the jail that real users would actually use to integrate their own AI tools safely. 

*Open question (do not design yet):* What is the interface for this? Is it a CLI wrapper that injects Warden into existing scripts? A Python SDK? A standard proxy layer? We will resolve this design when Phase 5 begins.

**Phase 5 Backlog / Known Issues (from Validation Milestone):**
- **TODO(phase5): Container directory state persistence.** Investigate if directory state (e.g., `mkdir project`) actually persists in the jail container across separate executor invocations, or if it only exists in the daemon's internal `_work_dir` tracking.
- **TODO(phase5): Argument ordering bugs.** Investigate potential scrambling of argument order during parsing/execution (e.g., `find` command throwing "paths must precede expression"). The `ShellParser` and/or `RealExecutor` may be incorrectly ordering flags vs positional args when reassembling commands.
---

## 12. Stack Decisions

| Layer | Choice | Status | Reasoning |
|---|---|---|---|
| Command parsing / policy engine / daemon core | **Python** | Current, v1.0 and beyond | Fast iteration, native subprocess handling, not on a performance-critical path. |
| Network enforcement — v1.0 (Phase 2) | **Python + NFQUEUE** (`netfilterqueue` + Scapy for parsing) | **Current plan, to be built in Phase 2** | Stays in the existing Python codebase; `netfilterqueue` provides actual packet-level enforcement (drop before forward), not passive sniffing. Fastest path to a working, demoable Phase 2. |
| Network enforcement — v2.0 (post Phase 4) | **Rust + eBPF/XDP** (`aya` or `libbpf-rs`) | **Explicitly deferred — not started** | Production-grade performance; sits on the hot path of every outbound packet. Requires different kernel capabilities (`CAP_BPF`/`CAP_SYS_ADMIN`) and a real rework of the docker-compose sidecar setup — not just a code swap. Do not start until Phases 1–4 are otherwise complete. |
| Container orchestration | **docker-compose** (sidecar pattern: `jail` + `warden-sidecar`) | Phase 2 architecture decided, not yet written | Agent jail remains unprivileged (`CAP_DROP: ALL`). Sidecar granted `CAP_NET_ADMIN` only. Internal bridge network. |
| Ledger | **SQLite** (Phase 1–3), evaluate Postgres or an event bus only if multi-agent/concurrent-session use demands it | Current | Zero-ops, file-based, sufficient for single-agent local use. |
| CLI client | Python (`textual` if a TUI is wanted) | Not started | Matches daemon language, thin and disposable by design. |
| Dashboard client | Undecided — plain local web app reading SQLite via a small API, or a TUI | Not started | Decide after Phase 1 demo, based on real usage, not speculatively. |
| Jail | **Docker**, read-only filesystem, stripped permissions | Dockerfile written, build pending | Not Warden's job to reinvent — Docker is the room, Warden is the guard. |

**Explicit non-decision (revisit later, don't decide now):** whether the daemon's control interface (for CLI to issue commands like reload-policy) is a Unix socket, a lightweight HTTP API, or a message queue. Any of these satisfy the "daemon + thin clients" contract — pick when the CLI is actually being built, not before.

---

## 13. Dev Environment (Mac)

- Core logic and policy rules are written and unit-tested directly on macOS with standard tools — no special setup needed for Phase 1 development.
- Integration testing (the actual jail behavior) runs through **Docker Desktop**, which transparently runs a lightweight Linux VM on macOS.
- Docker's shared-folder mount lets the isolated Linux agent environment write only into a bind-mounted directory, while Warden's daemon and ledger live on the host Mac filesystem — giving a realistic, production-shaped Linux sandbox without needing a separate machine.

---

## 14. Open Source Plan

Sequence (do not reorder):
1. Working Phase 1 demo, rehearsed, recorded.
2. Clean README explaining the problem and the core mechanic (the deception, not the whole roadmap) — lead with the demo GIF.
3. "Show HN: Warden" post once the README and demo exist — not before.
4. Open-core model: interceptor/daemon free and open; a hosted dashboard or team-features layer as the eventual paid tier, built only after there's real usage signal that people want it.

**Explicit guardrail:** do not open-source before the Phase 1 demo works end to end. The demo is the marketing. A half-working repo with a big roadmap README undersells this badly compared to a tight repo with a working GIF. Note: While this open-source guardrail remains absolute (Show HN will not happen until the GIF exists), development on Phase 2 is explicitly allowed to proceed in parallel in the meantime. The "Show HN" sequence does not block further codebase development.

---

## Changelog
- **0.1** — Initial spec created. Phase 1 scope finalized (structural parsing, policy-as-data, fake/real executors, unified ledger). Phase 2 network-enforcement mechanism corrected (passive Scapy sniff ≠ enforcement; NFQUEUE/eBPF needed for actual blocking). Architecture locked as headless daemon + thin read-only clients from the start.
- **0.2** — Phase 2 architecture finalized (2026-07-13). §7 rewritten from stub to full spec: sidecar container pattern via docker-compose; agent jail remains fully unprivileged; sidecar gets `CAP_NET_ADMIN` only. v1.0 mechanism: Python + NFQUEUE (`netfilterqueue`) for packet-level enforcement, Scapy for parsing only. v2.0 migration (Rust + eBPF/XDP) explicitly deferred with a clear note that it affects the container/orchestration layer, not just the code. Full component breakdown added (§7.4): docker-compose.yml, sidecar/Dockerfile, interceptor.py, PacketParser, NetworkInspector, policy.yaml network_rules extension, Ledger integration. Six sequential Antigravity prompts written (§7.6) — not executed. §10 stack table updated: NFQUEUE/Python as current v1.0 choice, eBPF/Rust as planned v2.0 migration, conditional framing removed.
- **0.3** — Documented stateless SNI filtering limitation in Phase 2 (§7.3) and scoped connection-tracking fix for Phase 2.5. Section numbers bumped accordingly.
- **0.4** — Clarified Phase 2.5 sequencing as post-Phase 4. Added "Validation Milestone" throwaway test before Phase 3, and "Phase 5 — Agent Integration Layer" as the final architectural piece. Section numbers bumped.
