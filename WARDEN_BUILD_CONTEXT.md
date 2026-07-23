# WARDEN — Builder Context & Continuity Log
### (read this before writing any code — this file is how you keep memory across sessions and accounts)

> **If you are an AI agent/IDE picking this repo up cold: read this entire file before touching code.**
> This file is NOT documentation for humans to admire — it is your working memory.
> **You are responsible for updating it.** Every session that adds, changes, or discovers
> something non-obvious ends with an update to §3 and §4 below. An unfinished session with no
> update to this file is an incomplete session, even if the code compiles.
>
> This file is separate from `WARDEN_SPEC.md`. That file holds architecture and vision and
> changes rarely. This file holds *current state* and changes constantly. If something here
> ever contradicts the spec, the spec wins on architecture decisions — flag the conflict in
> §5 (Open Questions) rather than silently resolving it.

---

## 0. How to Use This File (read this section every single session)

1. Read §1 (Conventions) once — it rarely changes, but never skip it on a fresh account/session.
2. Read §3 (Current State) and §4 (Handoff Note) — this tells you exactly where the last session stopped and why.
3. Do the work.
4. Before ending the session: update §3, overwrite §4 with a fresh handoff note, and append to §6 (Changelog) if a real decision was made. Do not leave stale state — the next session (possibly a different model, possibly a different Antigravity account) trusts this file completely and will act on it as truth.
5. If you're unsure whether something is "done," check for its tests, not just its file existing. A file that exists but has no passing test is `in_progress`, not `done`, in §3.

---

## 1. Code Conventions (rarely changes)

### Comment tags — use these, greppable, consistently, everywhere

Every non-trivial file should use these tags so intent can be reconstructed by grepping the repo, not by re-reading everything:

```
# CONTRACT: <what>       — marks an interface boundary (Inspector, Executor, Logger
                            method signatures, etc). Changing anything tagged CONTRACT
                            is a breaking change — check every implementer before touching it.

# WHY: <reasoning>        — marks a non-obvious decision. If a future model would
                            reasonably ask "why is this done this way instead of the
                            obvious way," answer it here, inline, at the point of decision.

# TODO(phaseN): <what>    — marks deferred work, tagged with which phase it belongs to
                            (e.g. TODO(phase2), TODO(phase3)) so a grep for TODO(phase1)
                            shows only what's actually in scope right now.

# RISK: <what>            — marks something that is a known weak point or shortcut
                            taken for speed, that should be hardened later. Different
                            from TODO — RISK means "this works but could fail/be bypassed
                            under X condition," not "this isn't built yet."
```

Keep these short. One line where possible. The next model reading this should get the "why" in five seconds, not have to reconstruct it from git blame.

### General rules

- Every module that implements a `CONTRACT`-tagged interface (Inspector, Executor, Logger) must have this stated explicitly at the top of the file, e.g. `# CONTRACT: implements Inspector.inspect() — see daemon/inspectors/base.py`.
- No inspector, executor, or rule logic changes the core loop (`daemon/core.py`). If a change seems to require touching the core loop, stop and reconsider — that's a signal the abstraction is being violated. Flag it in §5 rather than pushing through.
- Tests live next to the phase they belong to, not bundled generically. Prefer explicit test names describing the exact behavior locked in (e.g. `test_rule_precedence_most_specific_path_wins`), not `test_engine_1`.
- Never hardcode policy logic in Python. If you find yourself writing `if binary == "rm"` anywhere outside `policy.yaml`, stop — that belongs in the policy file.
- If you cannot locate prior content that a task references (a past draft, a decision, a file that should exist but doesn't) — say so explicitly and ask for it. Do not reconstruct it from nearby context, the spec, or your own inference and present it as if it were the original. A stated gap is recoverable; a silent reconstruction that looks complete is not, and it will pass review undetected until someone happens to compare it line-by-line against the real thing.
- NEVER print, echo, log, or otherwise output the literal value of any API key, secret, or credential — not in terminal commands run, not in files written, not in chat responses. If a secret needs to be set as an environment variable, tell the human the exact command to run themselves (e.g. "run: export GROQ_API_KEY=your-key-here" as an instruction, don't run it yourself with the real value filled in). Only ever reference secrets by their variable name, never their value.

### Frontend/visual work — hard gate, no exceptions without explicit override

Any task that produces something visual (a dashboard view, CLI screen layout, new page, new UI state) follows this sequence, in order, every time:

1. Write a plain-language visual spec into `design/<feature-name>/spec.md` (template in `design/README.md`). Cover: purpose, layout in words, data it reads (read-only from Ledger, per architecture), states it must handle (empty/loading/error/populated), and which aesthetic rules from `WARDEN_SPEC.md §9` apply.
2. **Stop.** Do not generate frontend code yet. The human reviews the spec and produces a rough mockup (Paint-style sketch or Stitch) into `design/<feature-name>/mockup/`.
3. Only once a mockup exists in that folder does frontend code generation begin, built against the approved mockup — not against the agent's own visual guess.

This gate is **absolute for anything user-facing.** It is skippable only if the human explicitly says so in the same session (e.g. "just build it plain, skip the mockup step") — never skip it by default or because it seems like a small UI change. Small UI changes are exactly where generic-looking defaults creep in.

### Hard Rules (Permanent Standing Rule Set)

- **Understanding Log Updates:** After any step that introduces a new concept, tool, library, or technique the developer hasn't used before, automatically add an entry to `WARDEN_UNDERSTANDING_LOG.md` without waiting to be asked. Follow the entry format exactly: Plain English then Technical, no analogies, each entry self-contained. Assume nothing is "too basic" to explain. Start every entry with a one-line anchor: what phase/component this is part of, and why it came up.
- **Commit Cadence:** At the end of every completed step (not every single message, but when a logical chunk of work is done), automatically stage and commit the project state. Use a clear, descriptive commit message. This provides a diffable history and removes the need to paste full file contents back and forth.
- **Destructive Git Commands:** ANY git command that discards commits or history (`reset --hard`, `force push`, `branch -D`, `checkout` that discards changes) requires explicit user approval BEFORE running it. No exceptions.

---

## 2. Repository Map (update if structure changes — cross-check against `WARDEN_SPEC.md §5`)

```
warden/
├── daemon/                    # see WARDEN_SPEC.md §3–6
├── clients/
├── jail/
├── tests/
├── design/                    # visual specs + mockups, see §1 above and design/README.md
├── WARDEN_SPEC.md              # architecture & vision — changes rarely
└── WARDEN_BUILD_CONTEXT.md     # this file — changes constantly
```

---

## 3. Current State

> Update this every session. Mark each item `not_started` / `in_progress` / `done` (done = has passing tests, not just exists).

**Active phase:** Phase 1 complete; Phase 2 complete. Validation Milestone complete. Phase 3 is next (Spec design updated, zero code written).

### Phase 3 — The Smart Policy Loop 🏗 SPEC DESIGN UPDATED

*Note: The design for Phase 3 has been revised. NO local LLM is needed. The detection work will use deterministic statistical methods (frequency counts, decision trees). Explanations will be template-based. A three-tier staging system and asymmetric scrutiny for permissive vs restrictive proposals will be introduced. This is a **SPEC-ONLY update**; zero Phase 3 code has been written.*

### Phase 1 — Smart Command Deception ✅ COMPLETE

| Component | Status | Notes |
|---|---|---|
| `daemon/parser/shell_parser.py` | done | 74/74 tests pass. Handles simple, chained (;/&&/||/pipe), $() and backtick substitution, quoted metacharacters, path resolution (macOS symlink-aware). |
| `daemon/inspectors/base.py` | done | Inspector ABC + Verdict + Decision enum. |
| `daemon/inspectors/command_inspector.py` | done | Binary + path-scope matching. Now the single source of truth for policy matching; returns Optional[Verdict]. |
| `daemon/rules/engine.py` | done | First-match-wins aggregation. Respects BLOCK as floor. No longer duplicates path matching logic. |
| `daemon/rules/policy.yaml` | done | 5 rules covering: destructive binaries, credential reads, privilege escalation, network exfiltration, project-dir allow-all. |
| `daemon/executors/base.py` / `real_executor.py` / `fake_executor.py` | done | Real uses subprocess (shell=False). Fake has per-binary table; dynamic fabrication for echo/grep/sed. |
| `daemon/ledger/schema.sql` / `logger.py` | done | Generic schema (event_type discriminator + JSON blob). WAL mode. Thread-safe. Never raises. |
| `daemon/core.py` + `demo/run_demo.py` | done | Full pipeline wired. Demo covers all 5 rules: 3 ALLOW+real executions, 6 BLOCK+fake, 3 FLAG+fake. Ledger shows 12 rows. Recording-ready output (no debug noise). |
| `design/` directory | done | Scaffolded, see §1 gate + `design/README.md` |
| `tests/` | done | 77 tests: test_parser.py, test_command_inspector.py, test_rule_engine.py, test_executors.py (includes e2e core loop tests). |
| `jail/Dockerfile` | done | Dockerfile written and tested via Validation Milestone. |

### Phase 2 — Network Guard ✅ COMPLETE

| Component | Status | Notes |
|---|---|---|
| Phase 2 architecture decision | done | Sidecar pattern via docker-compose. See `WARDEN_SPEC.md §7`. |
| `docker-compose.yml` | done | Written. Two services: `jail` (cap_drop ALL, no ledger mount) + `warden-sidecar` (cap_drop ALL, cap_add NET_ADMIN). Key decision: `network_mode: "service:jail"` — sidecar shares jail's network namespace so its iptables rules affect jail traffic. Jail has ZERO ledger volume access. |
| `sidecar/Dockerfile` | done | Written. python:3.11-slim + iptables + libnetfilter-queue-dev + netfilterqueue + scapy. Source code is NOT baked in — arrives via bind-mount at runtime. |
| `sidecar/interceptor.py` | done | Full NFQUEUE implementation with default-deny routing and ledger recording. |
| `daemon/parser/packet_parser.py` | done | 31/31 tests pass. ParsedNetworkAction subclasses ParsedAction (Inspector contract satisfied). TCP/UDP/OTHER parsing. Manual TLS ClientHello SNI extraction (no Scapy TLS layer dependency). DNS query name extraction (port 53 UDP). Direction inference via RFC1918 src IP heuristic. Never raises. |
| `daemon/inspectors/network_inspector.py` | done | 34/34 tests pass. Inspector contract satisfied (returns None for non-network actions). IP matching via ipaddress CIDR. Hostname: exact + single-label wildcard (RFC 6125). Port: int or "*". Default-deny (BLOCK) when no rule matches. |
| `daemon/rules/policy.yaml` — `network_rules` section | done | Written. 6 rules: OpenAI/Anthropic/Google allowlist (port 443), Docker bridge allow (172.16.0.0/12), loopback allow, catch-all BLOCK (0.0.0.0/0). |
| Ledger schema — network event compatibility | done | Zero schema changes. event_type + parsed_action JSON blob already designed for this. One logger.py change: ParsedNetworkAction branch in _serialise_parsed_action (without it, subclass fields silently dropped). 13/13 integration tests pass. |
| `demo/run_phase2_demo.py` | done | End-to-end demo: docker-compose up, jail makes network calls, sidecar intercepts, ledger shows mixed command+network rows. |

### Validation Milestone — Real Agent Test ✅ COMPLETE

| Component | Status | Notes |
|---|---|---|
| `demo/run_agent_test.py` | done | Full multi-turn ReAct loop using Anthropic/Llama. Employs `DockerJailExecutor`. Generates mixed ledger events in real-time. |
| `DockerJailExecutor` | done | Passes commands via `docker-compose exec`. Correctly handles `cwd` via host-to-container path synchronization. |
| Native Shell Redirection | done | `ShellParser` and `WardenDaemon` explicitly intercept and fulfill `>` and `>>` output redirection via Python, rather than relying on a shell. Tested explicitly. |
| Chain Re-parsing | done | `WardenDaemon` splits chained commands (e.g. `&&`) and parses them serially to capture intermediary `cd` updates into the active `work_dir` state. |

---

## 4. Backlog / Deferred Items

This is a living list of everything intentionally postponed across the whole project. Update it any time something gets deferred or an item gets picked up and resolved (move resolved items to a "Resolved" subsection with the date/commit, don't delete them).

- **Phase 2.5:** Stateless SNI filtering fix (needs conntrack) — `WARDEN_SPEC.md §7.3`.
- **v2.0:** eBPF/Rust migration for network interceptor — `WARDEN_SPEC.md §12` (deferred production path).
- **Phase 5:** Directory-state inconsistency across agent turns (`./project` appeared to vanish) — found during validation milestone.
- **Phase 5:** Argument-order scrambling in commands like `find` ("paths must precede expression") — found during validation milestone.
- **Phase 5:** General agent integration layer design not yet decided (CLI wrapper vs SDK vs other).
- **Phase 3:** FLAG-only ML inspector — named idea, not designed or built. See `WARDEN_SPEC.md §9`.
- **Phase 3:** LLM-based explanation generation for complex multi-factor patterns — open question, not committed. Revisit only if templating proves insufficient.
- **Phase 3 detection refinement (near-term):** CIDR-block clustering — group by /24 instead of requiring exact `dst_ip` match for the N=10/T=6h detection rule. Add once the exact-match rule has been validated against real ledger data and proves too coarse in practice (e.g. exfil to adjacent IPs in the same subnet not being caught). See `WARDEN_SPEC.md §9`.
- **Phase 3 detection refinement (longer-term, not scheduled):** Rate-of-change / burst detection relative to a rolling historical baseline, instead of a flat threshold. Deferred until enough historical ledger data exists for a meaningful baseline to be computed — meaningless to build before real usage data is available. See `WARDEN_SPEC.md §9`.
- **Daemon CLI:** Control interface protocol (Unix socket vs HTTP vs message queue) — explicit non-decision, deferred until CLI is built.
- **Jail Base Image:** `requests` package missing from jail image — deliberate decision, not an oversight (declined to expand attack surface).

### Resolved

- **Phase 3 Prerequisite:** Two-Ledgers Gap + Correlation Gap. Fixed via UDP IPC from sidecar to host daemon, using a pre-shared token and loopback socket, enforcing a single-writer pattern and resolving macOS virtiofs `EOPNOTSUPP` and WAL split-brain issues. Sidecar IPTables modified to exempt its own UDP IPC packets from NFQUEUE interception. See `WARDEN_SPEC.md §7.4`.
- **Phase 3 Tier 2 staging format/location:** Resolved. `proposed_rules` table in the daemon's existing SQLite DB — no new file, no new writer, consistent with the single-writer principle. Schema drafted in `WARDEN_SPEC.md §9`.

---

## 5. Handoff Note (overwrite this every session — do not append, replace)

```
Validation Milestone: COMPLETE. Real LLM agent loop running successfully against Warden.
Phase 3 Spec: UPDATED with new deterministic/template-based design. Zero code written yet.

Next step: write the detailed Phase 3 component breakdown + Antigravity prompts in `WARDEN_SPEC.md` §8 (or the current Phase 3 section), same as was done for Phase 1/2, before any code starts.

Findings & Backlog Items (Phase 5):
  - TODO(phase5): Investigate if container directory state (e.g. `mkdir project`) actually persists in the jail container across separate executor invocations, or if it only exists in the daemon's internal `_work_dir` tracking.
  - TODO(phase5): Investigate potential argument ordering bugs (e.g. `find` throwing "paths must precede expression"). The `ShellParser` and/or `RealExecutor` may be incorrectly ordering flags vs positional args when reassembling commands.
```

---

## 6. Open Questions / Conflicts (append, don't delete resolved ones — mark them resolved instead)

**RESOLVED** — Rule precedence: chose first-match-wins (iptables model). Documented in engine.py and locked in by TestRulePrecedenceFirstMatchWins tests.

**RESOLVED** — FLAG behaviour: FLAG → fake executor (treated as block). Marked distinctly in ledger as "FLAG" for Phase 3 triage.

**NOTE (not a conflict):** `ls /tmp` gets FLAG (default) not ALLOW in the demo because /tmp is outside `./project/**`. This is correct policy — the project-dir allow rule only covers `./project/**`. Adding a broader allow rule for read-only binaries outside the project is a policy decision, not an architecture decision. Document in README if confusing.

---

## 7. Changelog

- **Initial** — `WARDEN_BUILD_CONTEXT.md` created alongside `WARDEN_SPEC.md`. `design/` directory scaffolded with the visual-spec-before-code gate. No Phase 1 code written yet.
- **Phase 1 complete (2026-07-12)** — All 6 components implemented: Parser, Inspector interface + CommandInspector, RuleEngine + policy.yaml, RealExecutor + FakeExecutor, Ledger (schema + Logger), Core loop + demo script. 74 tests pass. Demo produces correct interception ledger. Rule precedence: first-match-wins (documented + test-locked). FLAG → fake executor (not allow). macOS symlink resolution handled in tests. Command substitution detection fixed to scan raw segment before shlex tokenisation.
- **Path-matching fix (2026-07-12)** — Relative path patterns (./project/**) in policy.yaml were not resolving against absolute target paths. Root cause: _path_matches_glob was purely static and had no work_dir context. Fixed by threading work_dir through RuleEngine, CommandInspector, and RealExecutor constructors. demo/run_demo.py updated to cover all 5 rules with 4 genuine ALLOW+real executions. project/ scaffold directory added.
- **ALLOW-rule addition + demo cleanup (2026-07-12)** — The original Phase 1 demo had zero genuine ALLOW executions: every command hit FLAG (default) or BLOCK. Added explicit project-dir ALLOW rule (Rule 5: `binary=["*"], path_scope=["./project/**"]`) and created the `project/` directory with sample files so ls/cat inside it execute for real and return real output. This is what makes the deception mechanic legible in the demo — you can see ALLOW+real alongside BLOCK+fake in the same ledger. demo/run_demo.py also cleaned up for recording: reason lines cleanly truncated, rule-coverage debug section removed, ledger table column widths fixed, output column left-trimmed.
- **Inspector Modularity Fix (2026-07-12)** — Fixed a major spec deviation where `RuleEngine` completely ignored `inspector_verdicts` and duplicated the rule matching logic from `CommandInspector`. Refactored so `CommandInspector` is the single source of truth for policy matching (returning `Optional[Verdict]`). `RuleEngine` now strictly aggregates verdicts, respecting `BLOCK` as a floor over `ALLOW`, and only uses the policy's `default_action` if no inspector produces a verdict. `WARDEN_BUILD_CONTEXT.md` was temporarily demoted to `in_progress` for this fix and returned to `done` after verifying the core loop and demo behavior remained unchanged but structurally sound.
- **README Restoration (2026-07-12)** — The prior cut-off session lost the original README draft (it was never committed to disk), a placeholder/reconstructed version was mistakenly written in its place, and this session restored the actual approved draft with the Phase 2 wording, install step, and test count corrected.
- **No-Silent-Reconstruction Rule (2026-07-12)** — Added a strict convention to §1: never silently reconstruct missing prior content (drafts, decisions, etc.) from context. If it cannot be located, explicitly say so and ask for it. This rule was added directly because of the README restoration incident, where reconstructed content was twice presented as verbatim without disclosure before the gap was caught.
- **Deferred Launch Sequence (2026-07-12)** — Updated `WARDEN_SPEC.md` and `WARDEN_BUILD_CONTEXT.md` to reflect a deliberate choice: the demo GIF, README embedding, and Show HN launch are deferred until after further development. This sequencing change explicitly unblocks Phase 2 to begin in parallel, while maintaining the rule that the repo won't be publicized until the GIF exists.
- **Jail Dockerfile written (2026-07-12)** — Created `jail/Dockerfile` and `jail/test_jail.sh`. Dockerfile uses python:3.11-slim, creates non-root user (uid 1000), and is designed to be run with `--read-only --cap-drop=ALL --security-opt=no-new-privileges --tmpfs /tmp`. test_jail.sh has 5 tests covering: container starts, non-root uid, read-only rootfs write rejection, /tmp tmpfs write allowed, NET_RAW cap drop. Build and test are PENDING — Docker Desktop was not running at time of writing.
- **Phase 2 architecture decided (2026-07-13)** — `WARDEN_SPEC.md §7` rewritten from stub to full spec. `WARDEN_BUILD_CONTEXT.md §3` updated with Phase 2 component table (all `not_started`). `§4` handoff note updated to reflect architecture decision and user note re: docker-compose explanations. `WARDEN_SPEC.md §10` stack table updated: conditional "if NFQUEUE/eBPF" framing replaced with explicit v1.0 (Python+NFQUEUE, current plan) and v2.0 (Rust+eBPF/XDP, explicitly deferred) rows. Zero Phase 2 code written.
- **Phase 2 Step 1 complete (2026-07-13)** — `docker-compose.yml`, `sidecar/Dockerfile`, and `sidecar/interceptor.py` (stub) written. Key decisions: (1) `network_mode: "service:jail"` — sidecar shares jail's network namespace so its iptables rules intercept jail traffic; (2) iptables chain = OUTPUT (not FORWARD) from within the shared namespace; (3) jail has zero ledger volume access — architectural rule, not a preference; (4) bridge is not `internal:true` — sidecar iptables is the enforcement, not Docker ACLs; (5) source code bind-mounted, not baked into image. nfnetlink_queue kernel module must be verified before Step 5.
- **Phase 2 Step 2 complete (2026-07-13)** — `daemon/parser/packet_parser.py` and `tests/test_packet_parser.py` written. 31 new tests, 108 total passing. `ParsedNetworkAction` subclasses `ParsedAction` directly — Inspector contract satisfied without changes to the ABC. SNI extraction is manual byte-level parsing of TLS ClientHello (RFC 5246) — no Scapy TLS layer dependency. DNS query name extraction via RFC 1035 label decoding. Direction inferred from RFC1918 src IP heuristic. `parse()` never raises.
- **Phase 2 Step 3 complete (2026-07-13)** — `daemon/inspectors/network_inspector.py` and `tests/test_network_inspector.py` written. 34 new tests, 142 total passing. Returns `None` for non-network actions (silent no-op in shell path). Default-deny: BLOCK when no rule matches. IP matching via `ipaddress` module (CIDR, `strict=False`). Hostname: exact + single-label wildcard (RFC 6125). `policy.yaml` extended with `network_rules` section: 6 rules covering LLM API allowlists, Docker bridge, loopback, and catch-all BLOCK.
- **Phase 2 Step 4 complete (2026-07-13)** — Ledger verified: zero schema changes needed. `schema.sql` was already designed for this (`event_type` discriminator + `parsed_action` JSON blob). One minimal `logger.py` change: added `isinstance(action, ParsedNetworkAction)` branch in `_serialise_parsed_action` — without it, subclass fields (`dst_ip`, `dst_port`, `protocol`, `hostname_or_sni`, `direction`) would be silently dropped. `raw_bytes` excluded from blob (binary, large). 13 new integration tests, 155 total passing.
- **Phase 2 complete (2026-07-13)** — `sidecar/interceptor.py` completed with full `netfilterqueue` integration. Added demo script (`demo/run_phase2_demo.py`) that successfully tests container routing, IP-based allowlisting, and ledger logging from within the sidecar. Documented stateless SNI filtering limitation in spec and scoped connection tracking for Phase 2.5.
- **Validation Milestone complete (2026-07-13)** — Built and successfully ran `demo/run_agent_test.py`, an autonomous agent loop (using LLMs) against Warden's `DockerJailExecutor`. Confirmed the agent makes dynamic decisions and Warden successfully intercepts and logs both ALLOW-scoped shell commands (creating dirs/files via native Python shell redirection) and BLOCKs out-of-bounds HTTPS requests at the packet level via the sidecar. Added Phase 5 TODOs for container directory persistence and argument ordering bugs.
- **Phase 3 Spec Revision (2026-07-14)** — Updated `WARDEN_SPEC.md` to reflect a revised design for the Smart Policy Loop. Arrived at through discussion, it was determined that an LLM is unnecessary for the core detection task since the underlying method can be a simple deterministic statistical/decision-tree approach. Explanations will use templates filled with real ledger numbers, keeping the system fully auditable. Introduced a Three-Tier Rule Staging System and Asymmetric Scrutiny for permissive vs restrictive proposals. This is a spec-only update; zero Phase 3 code has been written yet.
- **Correlation Gap Documented (2026-07-16)** — Added "The Correlation Gap" to `WARDEN_SPEC.md §7.4` and added an eBPF sourcing note to the v2.0 migration section. Discussion surfaced that Phase 3's advisor cannot reliably reason about cause-and-effect without fixing this gap first (linking shell events to network events). Documented env-var tagging (recommended), PID-based, and timestamp-window approaches.
- **Two-Ledgers Gap Found + Correlation Gap Revised (2026-07-19)** — Live testing confirmed the env-var and PID-based correlation approaches are not viable: jail and sidecar run in separate PID namespaces; `/proc/<pid>/environ` for jail processes is inaccessible from the sidecar. Deeper investigation revealed the Phase 2 "unified ledger" goal was never fully achieved — daemon and sidecar write to two completely separate SQLite files that have never been mounted in the same place. Updated `WARDEN_SPEC.md §7.4` with the compound fix: `pending_actions` table in the shared `warden_ledger` volume (correlation) + routing daemon shell event writes to the same volume (ledger unification). Backlog updated accordingly.
- **UDP IPC Fix Complete (2026-07-19)** — Successfully replaced sidecar SQLite writes with a UDP IPC link to the daemon. Daemon listens on `0.0.0.0:5005` (with UUID token auth) and performs a single-writer ledger insert. Solves the WAL split-brain issue across Docker Desktop macOS virtiofs. Discovered and fixed an infinite interception loop where the sidecar's `OUTPUT` NFQUEUE iptables rule caught and dropped its own UDP IPC packets by adding an explicit exception rule (`-p udp --dport 5005 -j ACCEPT`). 5x E2E tests passing 5/5.
- **Phase 3 detection design finalized (2026-07-23, spec-only)** — Starting detection rule: `(binary, dst_ip/hostname_or_sni)` exact-match frequency threshold, N=10 FLAGs within a rolling T=6h window generates a proposal. N=10/T=6h are explicitly named as starting constants expected to be tuned against real data. Template-based explanation format documented with the concrete fill-in structure. Tier 2 staging format resolved: `proposed_rules` table in the daemon's existing SQLite DB (first-draft schema in `WARDEN_SPEC.md §9`). CIDR-block clustering and rate-of-change/burst detection scoped out of the initial build and added as `§4` backlog items (near-term and longer-term respectively).
---

## 8. Note on Future Files (do not build yet — context only)

Phase 3 (`WARDEN_SPEC.md §8`, the Smart Policy Loop) will introduce a **separate, runtime file that Warden itself writes to** — a record of patterns the advisory model notices in the Ledger before proposing policy changes. That file is a *product feature of Warden*, lives inside the daemon's own data directory, and is read by the advisory loop and the human approver only. It is unrelated to this file and must not be merged with it when it's eventually built — this file is about *building* Warden; that future file is about *Warden's own runtime memory*. Do not create it now — there is nothing for it to do until Phase 3 exists.

