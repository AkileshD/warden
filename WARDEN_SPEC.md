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

#### RECOMMENDED FIX — Unix Socket IPC + Daemon as Sole Writer

*Note: An earlier design attempted to use a shared Docker volume with SQLite WAL mode to allow the daemon and sidecar to write to the same database concurrently. This was abandoned because virtiofs/osxfs on macOS Docker Desktop does not maintain `mmap` coherency for SQLite's `-shm` (shared memory) file across the host/Linux VM boundary. A 5-run e2e test revealed this caused a split-brain state where the sidecar's writes were invisible to the host daemon (failing 1 of 5 runs with "No network event found"). To fix the root cause, we must enforce a single-writer architecture.*

This fix relies on the principle that the daemon owns the stateful resource (the ledger), and everything else goes through it explicitly.

**Part 1 — Unix Socket IPC (solves cross-boundary writes):**

The sidecar is stripped of its database writing capabilities. Instead, it becomes a pure sender. It formats intercepted network events as JSON and sends them over a Unix Domain Socket (UDS) datagram socket (e.g., `/tmp/warden_ipc/warden.sock`). The daemon runs a background listener thread on this socket, receiving events and handling all database writes. A shared directory (`/tmp/warden_ipc`) is bind-mounted between the host and the sidecar container to share the socket file.

**Part 2 — `pending_actions` table (solves correlation):**

When the daemon dispatches a command for real execution, it writes one row to a `pending_actions` table in the SQLite file immediately before `subprocess.Popen` returns:

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

When the sidecar intercepts a packet, it captures the current timestamp (`packet_timestamp`) and sends it along with the network event data over the IPC socket. When the daemon receives this event, *the daemon* queries `pending_actions` for rows where `dispatched_at` is within ±N seconds of the packet timestamp. The daemon tags the network event with the matched `action_id`, and writes it to the ledger.

**Part 3 — Ledger unification (solves the two-ledgers gap):**

Because the daemon now receives network events directly from the sidecar, the daemon simply writes both shell and network events to its configured `warden_demo.db`. Phase 3 will have a single SQLite file containing all events, linked by `action_id`, queryable with a plain JOIN.

#### Implementation Breakdown — UDP IPC Fix (Final Architecture)

This section documents the final implemented architecture for the daemon-sidecar IPC, enforcing a single-writer ledger model over UDP. (Note: `AF_UNIX` sockets were originally planned but abandoned due to `EOPNOTSUPP` virtiofs limitations across the macOS/Linux boundary).

##### IPC Access: How the Sidecar Reaches the Daemon
The daemon creates a UDP socket bound to `0.0.0.0:5005` on the host. To prevent trivial event injection, the daemon generates a random UUID4 authentication token at startup, writing it to `ipc_data/token.txt`. `docker-compose.yml` bind-mounts this directory read-only into the sidecar. The sidecar reads the token and sends UDP datagrams containing network events to `host.docker.internal:5005`.

##### Component Breakdown

**`daemon/ledger/schema.sql`**
Adds the `pending_actions` table.
```sql
CREATE TABLE IF NOT EXISTS pending_actions (
    action_id     TEXT PRIMARY KEY,
    dispatched_at REAL NOT NULL,
    binary        TEXT NOT NULL,
    args          TEXT NOT NULL,
    pid           INTEGER,
    expires_at    REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_pending_actions_dispatched
    ON pending_actions(dispatched_at);
```

**`daemon/ledger/logger.py`**
Adds methods to manage `pending_actions` and correlate:
- `write_pending_action(action_id, dispatched_at, binary, args, pid=None, ttl=60.0)`
- `update_pending_action_pid(action_id, pid)`
- `resolve_pending_action(packet_timestamp, window_seconds=5.0)` — returns `action_id` or `None`.
- `cleanup_pending_actions()`

**`daemon/ipc_listener.py`**
A background thread managing the UDP listener.
- Binds to `0.0.0.0:5005`.
- Writes a UUID4 token to `/tmp/warden_ipc/token.txt`.
- Receives JSON network events.
- Silently rejects payloads without a matching token.
- Calls `logger.cleanup_pending_actions()` and `logger.resolve_pending_action(packet_timestamp)`.
- Reconstructs `LedgerEvent` with the `action_id` and calls `logger.record()`.

**`daemon/core.py`**
- Starts `IPCListener` during `WardenDaemon.__init__` and shuts it down in `.close()`.
- In `_process_single()`, generates `action_id`, calls `write_pending_action`, executes the subprocess to get the PID, and updates `update_pending_action_pid`.

**`daemon/executors/real_executor.py`**
Surfaces the subprocess PID in `ExecutionResult` using `subprocess.Popen` + `.communicate()`.

**`sidecar/interceptor.py`**
- Uses `get_token()` to read the token file.
- Formats the network event as JSON, includes the token, and sends via `socket.AF_INET`, `SOCK_DGRAM` to `host.docker.internal:5005`.
- **Crucial Exemption Rule**: Because the sidecar uses `NFQUEUE` on the `OUTPUT` chain, it intercepts *all* outbound traffic, including its own UDP IPC packets. This triggers an infinite interception loop where the sidecar drops its own IPC packets. To fix this, an exemption rule is inserted *before* the NFQUEUE rule:
  `iptables -I OUTPUT -p udp --dport 5005 -j ACCEPT`

**`docker-compose.yml`**
Removes the `warden_ledger` volume entirely. Adds the IPC bind-mount and network routing parameters:
```yaml
    volumes:
      - .:/app:ro
      - ./ipc_data:/tmp/warden_ipc:ro
    environment:
      - PYTHONPATH=/app
      - WARDEN_UDP_HOST=host.docker.internal
      - WARDEN_UDP_PORT=5005
      - WARDEN_TOKEN_PATH=/tmp/warden_ipc/token.txt
```
To ensure `host.docker.internal` resolves correctly for the sidecar (which shares the jail's network namespace), the `jail` service explicitly configures:
```yaml
    extra_hosts:
      - "host.docker.internal:host-gateway"
```

##### Testing Plan (Completed successfully 5/5)
1. **`pending_actions` row written on real dispatch.**
2. **Network event gets sent and tagged.**
3. **No Database Locking/Missing Events:** Verified across 5/5 sequential clean runs.

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

1. **No Local LLM Required:** The core detection work must use a simple, deterministic statistical method. Using an LLM for detection would reintroduce the opacity problem the rest of Warden deliberately avoids — a frequency threshold can be inspected directly ("this fired because count ≥ N within window T"). This extends the "not an LLM making decisions" principle from the enforcement path to the advisory path as well.

2. **Template-Based Explanations:** Explanations for proposed rules are templated, not LLM-generated. Because detection relies on structured data (exact counts, thresholds, matched fields), the reasoning for any proposal is generated by filling in a fixed template with real ledger numbers. This guarantees full auditability — every number traces back to a ledger query. The template format is:

   > Pattern detected: **N** occurrences of `<binary>` → `<destination>` with FLAG verdict over **T** hours (threshold: N=10, T=6h). Proposed rule: `<yaml_rule_snippet>`. Historical replay: would have changed **A** of **B** matching events from FLAG to BLOCK.

   *(If genuinely complex multi-factor patterns arise later where templating feels insufficient, revisit whether a short natural-language summary step is worth adding — but do not build this speculatively.)*

3. **Starting Detection Rule — Exact-Match Frequency Threshold:**
   The first and only detection rule for the initial build uses asymmetric grouping:

   > **For shell-origin events: When a specific `binary` + `dst_ip` combination OR a specific `binary` + `hostname_or_sni` combination receives a `FLAG` verdict ≥ N=10 times within a rolling T=6-hour window, generate a proposed rule.**
   > 
   > **For network-origin events: When a specific `dst_ip` OR a specific `hostname_or_sni` (ignoring binary) receives a `FLAG` verdict ≥ N=10 times within a rolling T=6-hour window, generate a proposed rule.**

   **WHY the asymmetry:** Network enforcement (`policy.yaml` `network_rules`) can only ever act on destination/port. It cannot act on the originating binary. Therefore, merging network-origin `FLAG` events across all binaries for a destination-only threshold produces the correct signal. Breaking network events out by binary would incorrectly fragment the threshold count for a single malicious destination. Shell-origin events, however, are enforced by binary, so they retain the `(binary, destination)` grouping.

   **N=10 and T=6h are initial starting constants, not fixed values.** They are expected to be tuned once real proposals are seen against real ledger data. The detection algorithm runs **two independent SQL queries** per event type (one grouped by IP, one grouped by hostname) and generates a proposal if either crosses the threshold. This "separate axes" design ensures that an IP hit with and without SNI is correctly grouped and caught on the IP axis.

   Refinements such as CIDR-block clustering (grouping by /24 instead of exact IP) and rate-of-change/burst detection are explicitly **not** part of this initial build — they are captured in `WARDEN_BUILD_CONTEXT.md §4` as near-term and longer-term backlog items respectively, to be revisited once the N=10/T=6h exact-match rule has been validated against real data.

4. **Three-Tier Rule Staging System:**
   - **Tier 1 (`policy.yaml`):** The permanent, enforced ruleset. Only ever edited by a human, directly or via explicit approval.
   - **Tier 2 (`proposed_rules` table):** The advisory system writes candidate rules here with their template-generated reasoning. Nothing in this table is enforced — it is a staging area only. The table lives in the **same SQLite database the daemon already owns** (consistent with the single-writer principle established in Phase 2's correlation fix; no new file, no new writer). Draft schema:

     ```sql
     CREATE TABLE IF NOT EXISTS proposed_rules (
         proposal_id       TEXT PRIMARY KEY,       -- UUID
         created_at        REAL NOT NULL,          -- Unix timestamp
         detection_rule    TEXT NOT NULL,          -- e.g. 'exact_match_frequency_v1'
         matched_binary    TEXT NOT NULL,          -- e.g. 'curl'
         matched_destination TEXT NOT NULL,        -- dst_ip or hostname_or_sni
         detection_axis    TEXT NOT NULL           -- 'ip' or 'hostname'
                           CHECK(detection_axis IN ('ip', 'hostname')),
         occurrence_count  INTEGER NOT NULL,       -- how many FLAGs triggered this
         window_start      REAL NOT NULL,          -- start of the detection window
         window_end        REAL NOT NULL,          -- end of the detection window
         proposed_yaml_rule TEXT NOT NULL,         -- the candidate policy.yaml snippet
         status            TEXT NOT NULL           -- 'pending' | 'approved' | 'rejected'
                           CHECK(status IN ('pending','approved','rejected')),
         reasoning_text    TEXT NOT NULL           -- filled template (the human-readable explanation)
     );
     ```

     This schema is a **first draft**, subject to refinement once the detailed component breakdown is written. Columns may be added or renamed during implementation.

   - **Tier 3 (Dry-Run Testing):** Before any proposed rule is approved into `policy.yaml`, it must be replayed against historical ledger data, producing a concrete "here's what would have changed" report (counts of affected ALLOW/BLOCK/FLAG events). Approval is based on this concrete evidence, not just the proposal's text.

5. **Asymmetric Scrutiny:** Proposals that make policy MORE RESTRICTIVE (e.g. FLAG → BLOCK) can go through lightweight approval. Proposals that make policy MORE PERMISSIVE (e.g. adding a new ALLOW) must require deliberately harder, more explicit confirmation — that is the direction from which real harm would come. This asymmetry must be a structural part of the approval flow, not just an informal norm.

6. **FLAG-Only ML Inspector (Scoped Idea):** A lighter-weight, non-enforcing companion that could precede the full advisory loop — an inspector that can *only* ever return `FLAG` (never `BLOCK` or `ALLOW`), adding an extra signal to the ledger without any risk of enforcement. *(Do not design now; keep as a scoped backlog idea.)*

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

### 11.1 Architecture: Single Unix Socket, Multiple Clients

The daemon exposes **one standing local Unix domain socket** (e.g. `/var/run/warden.sock`). Every external tool that needs to talk to the daemon — the CLI wrapper, the SDK, the approval CLI, the dashboard — is just a client of that socket. There are no competing transport mechanisms; the socket is the single control plane.

**Part 1 Scope: Immediate Execution Plane**
- **`warden daemon start`**: The single bootstrap command. It runs `docker-compose up -d` (jail + sidecar) AND starts the daemon's socket listener, in that order. One command brings up the entire environment.
- **`warden exec <cmd>` (CLI wrapper)**: Thin command-line shim. Sends a command string over the socket, receives the verdict + execution result.
- **`demo/run_agent_test.py`**: The agent test harness loop is migrated to call through this socket rather than importing `DockerJailExecutor` in-process. 
*(Note: Transparent/automatic OS-level interception like PATH shims or ptrace are explicitly out of scope for this build and deferred as a future stretch goal).*

**Part 2 Scope: Future Developer & Review Plane (DEFERRED)**
- **Python SDK / client library**: Programmatic equivalent of the CLI wrapper. A single `warden.exec(cmd)` call that handles the socket protocol internally.
- **Approval CLI / TUI**: Human-facing tool for reviewing `proposed_rules` and querying the ledger.
- **Future dashboard**: Web-based read-only view of the ledger and pending proposals.
*These are real, planned components and must be built eventually, but they are explicitly excluded from Part 1 to maintain focus on the execution path.*

### 11.2 Socket Protocol & Switchboard Routing

The socket reads a JSON payload containing the command and an `executor` field. This acts as a switchboard:
- `executor="docker_jail"` (default): Routes the command to the `DockerJailExecutor` (the primary sandboxed path).
- `executor="host"`: Routes the command to the `RealExecutor` on the host OS. (Wired for completeness, but not expected to see real use yet).

### 11.3 Authentication (Phase 5 v1)

**None for this pass.** The socket file's OS-level permissions are the only access control.
*TODO(phase5): If/when this needs to be exposed beyond local processes, adopt the token-auth precedent already established by the sidecar's UDP IPC listener (`ipc_listener.py`).*

**WHY Unix socket over HTTP or a message queue:**
Everything here is same-machine communication. The daemon, the agent, the CLI, and the jail all run on the same host. A Unix socket provides the fastest possible IPC with zero network overhead, zero TLS configuration, and natural filesystem-level access control (socket file permissions). HTTP would add unnecessary serialization ceremony and a TCP stack for localhost traffic. A message queue (Redis, ZMQ, etc.) would add an external dependency for a problem that doesn't need one. This is the same reasoning that drove the Phase 2 sidecar's UDP IPC choice: pick the simplest transport that matches the actual deployment topology.

### 11.4 Scope Boundary — What Warden Can and Cannot Integrate With

**Realistic integration target:** Custom-built agents and direct API-key-based loops where the builder controls the execution path. Examples: a hand-rolled ReAct loop calling Anthropic/Groq directly, a LangChain agent with a custom tool executor, any framework where the developer can replace the "run this shell command" step with `warden exec <cmd>`.

**Not integrable (by design limitation of the product, not Warden):** Sealed consumer products — GitHub Copilot, Antigravity, Cursor's built-in agent, etc. — where the product controls command execution internally and does not expose a hook to replace it. Unless such a product exposes an MCP-based override (or similar plugin mechanism) that lets a custom tool replace their built-in command-execution tool, Warden cannot intercept their commands. This is a limitation of what those products currently allow, not a gap in Warden's design, and should not be treated as a bug to fix later.

### 11.5 Phase 5 Backlog / Known Issues (from Validation Milestone)

- **RESOLVED(phase5): Container directory state persistence.** State *does* persist correctly via the bind mount; the reported bug was actually a string-prefix path-translation error in Python (`DockerJailExecutor`), now fixed. See `WARDEN_BUILD_CONTEXT.md §4` (Resolved) for full detail.
- **TODO(phase5): Argument ordering bugs.** Investigate potential scrambling of argument order during parsing/execution (e.g., `find` command throwing "paths must precede expression"). The `ShellParser` and/or `RealExecutor` may be incorrectly ordering flags vs positional args when reassembling commands.
---

## 12. Phase 6 — Packaging & Distribution (future, not started)

**Goal:** Make Warden installable and runnable by developers who aren't the author. Currently, Warden is a development-time tool that requires Docker Desktop as a hard dependency — the jail, the sidecar, and the inter-container networking all run on Docker.

### 12.1 Current Decision: Ship as "Requires Docker"

For v1.0, Warden ships as a developer tool that explicitly requires Docker Desktop (macOS/Linux) or Docker Engine (Linux). This is an acceptable dependency for the target audience (developers building custom AI agent loops), and avoids the significant engineering cost of replacing Docker's container isolation with native OS sandboxing.

### 12.2 Deferred: No-Docker-Required Packaging

Replacing Docker with native OS sandboxing (Linux namespaces + seccomp, macOS `sandbox-exec`, etc.) is explicitly deferred as its own future milestone. This would eliminate the Docker Desktop dependency entirely, making Warden a standalone binary/package that creates its own sandbox.

**Note:** This milestone may fold into the already-planned v2.0 eBPF/Rust migration (see §13 Stack Decisions). Both efforts would remove the Docker Desktop dependency as a side effect, even though they are motivated differently:
- **v2.0 eBPF/Rust migration** is motivated by *performance* (moving network enforcement off the NFQUEUE hot path).
- **No-Docker packaging** is motivated by *distribution* (reducing install friction for end users).

If both happen, they should be coordinated to avoid building a native sandbox layer in Python only to rewrite it in Rust immediately after. Do not design the packaging mechanism itself until this work is actually scheduled.

---

## 13. Stack Decisions

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

**Resolved:** The daemon's control interface is a **Unix domain socket** (see §11.1). This was previously an explicit non-decision; it was resolved when the Phase 5 architecture was designed. The reasoning (same-machine IPC, no external dependencies, filesystem-level access control) is documented there.

---

## 14. Dev Environment (Mac)

- Core logic and policy rules are written and unit-tested directly on macOS with standard tools — no special setup needed for Phase 1 development.
- Integration testing (the actual jail behavior) runs through **Docker Desktop**, which transparently runs a lightweight Linux VM on macOS.
- Docker's shared-folder mount lets the isolated Linux agent environment write only into a bind-mounted directory, while Warden's daemon and ledger live on the host Mac filesystem — giving a realistic, production-shaped Linux sandbox without needing a separate machine.

---

## 15. Open Source Plan

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
- **0.5** — Phase 3 detection design finalized (spec-only, no code). Starting detection rule: exact-match frequency threshold N=10 / T=6h on `(binary, dst_ip/hostname)` + `FLAG` verdict. Template-based explanation format documented. Tier 2 staging resolved: `proposed_rules` table in the daemon's existing SQLite DB (single-writer principle preserved). CIDR-block clustering and rate-of-change detection explicitly scoped out of initial build and captured in `WARDEN_BUILD_CONTEXT.md §4` backlog.
