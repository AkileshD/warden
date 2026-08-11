# war(den)

> The AI agent thinks it deleted your files. It didn't.

war(den) is a fake shell that sits between an AI agent and your operating
system. When the agent runs a dangerous command — `rm -rf /`, reading your
`.env`, exfiltrating data over `curl` — war(den) intercepts it, returns a
convincing fake response (exit 0, no output, just like success), and writes
the attempt to a tamper-proof ledger. The OS is never touched.

The agent has no idea it's in a cage.

---

[DEMO GIF HERE]

---

## How it works

1. **Intercept** — every shell command the agent issues passes through
   war(den)'s parser before reaching the OS.
2. **Evaluate** — a policy engine checks the command against a YAML rule file
   (binary name + path scope). First matching rule wins.
3. **Execute or fake** — ALLOW commands run for real. BLOCK and FLAG commands
   run against a fake executor: the OS is untouched, exit code is 0, stdout
   is fabricated to look plausible.
4. **Log** — every command, verdict, and output is appended to an append-only
   SQLite ledger. The agent sees nothing. You see everything.

```
ALLOW  ls ./project/                  real   README.md src tests
BLOCK  rm -rf /                       fake   (silent — OS untouched)
BLOCK  cat ../../.env                 fake   (silent — OS untouched)
FLAG   curl https://...               fake   (logged for review)
ALLOW  ls ./project/; rm -rf /        ← chained: ls is real, rm is faked
```

## Try it

```bash
git clone https://github.com/AkileshD/warden
cd warden
pip install -r requirements.txt

# Start the Warden daemon in one terminal:
./warden daemon start

# In a separate terminal, run the agent test loop:
python3 demo/run_agent_test.py
```

Requires Python 3.11+. No network access. No install step beyond PyYAML.

## Policy

Rules live in `daemon/rules/policy.yaml`. Policy is data, not code — add a
rule, save the file, it hot-reloads.

```yaml
rules:
  - name: block-destructive-outside-project
    match:
      binary: ["rm", "dd", "shred", "mkfs"]
      path_scope: ["!./project/**"]
    action: block
    risk: high
  - name: allow-inside-project
    match:
      binary: ["*"]
      path_scope: ["./project/**"]
    action: allow
    risk: low
```

Three verdicts:

| Verdict | What happens |
|---|---|
| ALLOW | Command runs for real |
| BLOCK | Faked silently. Logged. OS untouched. |
| FLAG | Faked. Logged. Flagged for human review. |

## Run the tests

```bash
python3 -m pytest tests/ -v
```

346 tests. Should be green on any POSIX system with Python 3.11+.

## Roadmap

These are not built. They are not promised. They are the intended direction.

- **Phase 5 Part 2** — Agent Integration Layer (Python SDK & Dashboard)
- **Phase 6** — Packaging/distribution (ship as "requires Docker" for v1.0)
- **v2.0** — eBPF/Rust migration for network interceptor

## Why this approach

Most agent sandboxes work by restricting what the agent can do (allowlists,
containers, permission systems). war(den) works differently: the agent can
issue any command. It just doesn't always execute it. Deception-based
containment is harder for an agent to reason around than a permission
error — there's nothing to retry, no error to handle, no signal that
anything went wrong.

## Status

- **Phase 1** (Command Interception) — **COMPLETE**
- **Phase 2** (Network Guard via Sidecar) — **COMPLETE**
- **Phase 3** (Smart Policy Loop) — **COMPLETE**
- **Phase 4** (Minimalist TUI) — **COMPLETE**
- **Phase 5** (Agent Control Socket) — **COMPLETE (Part 1)**

MIT License
