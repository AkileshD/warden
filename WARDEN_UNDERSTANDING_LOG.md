# WARDEN — Understanding Log (Personal, gitignored)
### This file is for the developer's own learning. It is NOT part of the public repo, NOT read by fresh build sessions as project context, and NOT a substitute for WARDEN_SPEC.md or WARDEN_BUILD_CONTEXT.md.

> **Instruction to the build agent:** after any step that introduces a new
> concept, tool, library, or technique the developer hasn't used before,
> add an entry here — don't wait to be asked. Write for someone learning
> this for the first time: skip analogies, skip filler, just explain
> plainly and then technically. Assume nothing is "too basic" to explain.
> Every entry must be understandable on its own — if the developer pastes
> just one entry into a different LLM chat with zero other context, that
> LLM should be able to help them from the entry alone. Start every entry
> with a one-line anchor: what phase/component this is part of, and why
> it came up.

---

## How Entries Are Structured

```markdown
### <Concept Name>
**Part of:** Phase N — <component/step this came up in>
**Why it came up:** <one line — what problem or decision led here>

**Plain English:**
<What it is and why it matters. No jargon left unexplained. No analogies —
just the real thing, described simply.>

**Technical:**
<The actual mechanism. Minimal code — just enough to anchor the concept,
not a full implementation. Reference the real file/function in the repo
where this is actually used, so it's easy to go look at the real thing.>
```

---

## Phase 1 — Smart Command Deception

### Inspector pattern / interface contract
**Part of:** Phase 1 — `daemon/inspectors/base.py` and implementers
**Why it came up:** Warden needs a consistent way to evaluate different types of actions (shell commands, network traffic) without tangling all the specific logic together.

**Plain English:**
An interface contract is a strict rule about what a piece of code must accept as input and what it guarantees to return as output. It creates a standardized "plug" for different modules. The Inspector pattern means Warden has a central core that just asks a list of independent "Inspectors" what to do. The core doesn't care *how* an Inspector makes its decision; it only cares that every Inspector accepts a parsed action and returns an ALLOW, BLOCK, FLAG, or None.

**Technical:**
In `daemon/inspectors/base.py`, the `Inspector` class is defined as an Abstract Base Class (ABC) with a single method signature: `def inspect(self, action: ParsedAction) -> Verdict | None`. This is the contract. Both `CommandInspector` and `NetworkInspector` implement this exact signature. The main `daemon/core.py` loop just loops over all registered inspectors and calls `.inspect(action)`. Because of the contract, adding a new type of inspector in the future requires exactly zero changes to the core loop.

### shlex-based command parsing and shell metacharacters
**Part of:** Phase 1 — `daemon/parser/shell_parser.py`
**Why it came up:** We needed to accurately understand what a raw string of shell text actually means before evaluating it against our rules.

**Plain English:**
When a user types a command like `cat "my file.txt"`, the spaces inside the quotes are part of the filename, not separators between two different files. If we just split the string by spaces, we break the command. `shlex` (shell lexical analyzer) is a built-in Python tool that splits strings the exact same way a real Unix shell does, respecting quotes and escapes. A "metacharacter" is a symbol that tells the shell to do something special (like `|` to pipe output or `>` to write to a file), and we have to extract those out so we know exactly what program is actually running.

**Technical:**
The `ShellParser` uses `shlex.split(raw_input)` to turn raw strings into a list of tokens. It then iterates through the tokens looking for shell operators (`|`, `>`, `>>`, `&`, etc.). When it finds one (like a pipe `|`), it knows that whatever comes next is an entirely new command. It breaks the string down into a primary `ParsedAction` and nested `sub_commands`. This prevents the agent from bypassing rules by doing something sneaky like `echo "hello" | malicious_command`, because the parser extracts `malicious_command` as a distinct action for the inspector to evaluate.

### Policy-as-data approach
**Part of:** Phase 1 — `daemon/rules/engine.py` and `policy.yaml`
**Why it came up:** We needed rules for what commands are allowed, but writing `if command == "rm": block()` directly into Python code creates an unmaintainable mess.

**Plain English:**
"Policy as data" means separating *what* the rules are from *how* they are enforced. Instead of hardcoding the rules into the actual programming logic, you write the rules in a plain, readable configuration file (like a YAML file). The Python code is just an engine; it reads the config file and enforces whatever it finds there. This means you can change your security rules on the fly just by editing a text file, without ever touching or rewriting the core software.

**Technical:**
Warden uses `daemon/rules/policy.yaml` to define arrays of allowed paths, blocked commands, and flags. The `RuleEngine` class (instantiated inside `CommandInspector`) loads this YAML file into memory as a dictionary. When an action comes in, the engine checks the parsed command against the data in the YAML structure. If a path or binary needs to be allowed, it is added to the YAML, requiring zero changes to the `engine.py` execution logic.

### SQLite basics and WAL mode
**Part of:** Phase 1 — `daemon/ledger/logger.py` and `schema.sql`
**Why it came up:** Warden needs a persistent, queryable database to log everything the AI agent does without the overhead of running a full database server like PostgreSQL.

**Plain English:**
SQLite is a complete, relational database system that lives entirely inside a single file on your hard drive. There is no separate "server" running in the background; the database engine is just a library that your Python script imports. WAL (Write-Ahead Logging) is a specific setting for SQLite that makes it much faster and safer. Instead of pausing all readers every time it needs to write new data to the file, it appends the new data to a temporary "log" file first, allowing reading and writing to happen at the exact same time without locking up.

**Technical:**
The `LedgerLogger` uses Python's built-in `sqlite3` library. The `schema.sql` defines the `events` table with standard SQL columns (id, timestamp, event_type, verdict, etc.). During initialization, we execute `PRAGMA journal_mode=WAL;`. This creates a `-wal` file on disk next to `warden_demo.db`. When an inspector returns a decision, the logger executes an `INSERT INTO events` statement. Because of WAL mode, Warden can write thousands of log entries per second without blocking UI tools that might be simultaneously reading the database to display a dashboard.

### Real-vs-fake executor / Deception mechanic
**Part of:** Phase 1 — `daemon/executors/real_executor.py` and `fake_executor.py`
**Why it came up:** The core premise of Warden is that when an AI agent does something malicious, we don't just block it—we trick the agent into thinking it succeeded.

**Plain English:**
If an AI agent tries to delete an important file and Warden just throws an "Access Denied" error, the agent will know it's being blocked and might try other ways to attack. The deception mechanic intercepts the dangerous command and hands it to a "Fake Executor" instead. The fake executor pretends to run the command, silently does absolutely nothing to the real files, and returns a fake "success" message back to the agent. The agent moves on, believing the file is gone.

- **Stateful Directory Tracking (Phase 1/2 Bridging):** The Phase 1 daemon intercepts chained shell commands by evaluating each sub-command independently (so `cd` and `rm` are judged separately). To prevent `cd` from being stateless across these independent executions (which broke `cd test && touch file.py`), `WardenDaemon` must track its internal `_work_dir` and update it on a successful `cd`, then pass it via `--workdir` to subsequent `docker-compose exec` calls.
- **Network & Shell Correlation Gap (Phase 3 Prep):** Currently, network events logged by the sidecar have no `session_id` attached to them, making it impossible to directly correlate a specific network request with the shell command that triggered it in the same test run. This is a real architectural gap that must be addressed in Phase 3 (The Smart Policy Loop) because the LLM will need to correlate shell intent with network outcomes to propose meaningful policy updates.

**Technical:**
In `daemon/core.py`, after an action is inspected, a `Verdict` is returned. If the verdict is `ALLOW`, the action is passed to the `RealExecutor`, which uses Python's `subprocess.run()` to actually execute the binary on the host filesystem and return the true `stdout`/`stderr`. If the verdict is `BLOCK` or `FLAG`, the action is passed to the `FakeExecutor`. The `FakeExecutor` matches the `ExecutionResult` data class contract exactly, but returns an empty string for `stdout` and a `0` exit code. To the shell communicating with the agent, there is no technical difference between the two executors' return values, achieving perfect deception.

---

## Phase 2 — The Network Guard

### Docker containers/images
**Part of:** Phase 2 — `jail/Dockerfile` and `sidecar/Dockerfile`
**Why it came up:** Warden needs a strictly isolated environment for the AI agent to run in, and a separate one for the network interceptor.

**Plain English:**
An "image" is a static snapshot of an environment: it contains a bare-bones operating system (like Linux), system libraries, and pre-installed software. A "container" is a running instance of that image. It is an isolated process running on the host machine that thinks it is a complete computer, but is actually sharing the host computer's operating system kernel. It only has access to its own isolated file system, network interfaces, and process tree.

**Technical:**
Containers use Linux namespaces to isolate resources (PID namespace for processes, net namespace for networking, mount namespace for the filesystem) and cgroups to limit resource usage (CPU/memory). In Warden, `jail/Dockerfile` defines the static image for the agent, pulling from a minimal Linux base (`python:3.11-slim`), installing tools, and creating an unprivileged user. When this image is run as a container, the agent executes inside it without being able to see or interact with the host Mac's actual files or processes.

### Linux capabilities (cap_drop/cap_add)
**Part of:** Phase 2 — `docker-compose.yml` and `jail/test_jail.sh`
**Why it came up:** Docker containers run as root by default and have too much power; we need to strip the agent's power and grant the interceptor specific network powers.

**Plain English:**
Historically, Linux users were either normal users (who could only touch their own files) or the "root" superuser (who could do absolutely anything, including modifying the kernel or changing network routing). Linux capabilities break the "root" superpower down into a checklist of specific powers. Instead of giving a process "root", you can give it just one specific superpower (like the ability to change network settings) while keeping it unprivileged otherwise.

**Technical:**
A capability is a bitflag checked by the Linux kernel before allowing privileged operations. By default, Docker containers get a subset of capabilities. In Warden's `docker-compose.yml`, the `jail` service uses `cap_drop: ["ALL"]`, which tells Docker to strip every single capability from the container. The agent cannot load kernel modules, change network routes, or use raw sockets (preventing ping/raw IP spoofing). Conversely, the `warden-sidecar` service uses `cap_drop: ["ALL"]` but adds `cap_add: ["NET_ADMIN"]`, granting it exactly the one power it needs: the ability to configure `iptables` and manage network packet queues.

### The sidecar container pattern
**Part of:** Phase 2 — Network Interception Architecture
**Why it came up:** Warden needs to intercept the agent's network traffic without putting the interception code inside the agent's own container.

**Plain English:**
Instead of putting two different pieces of software into one container, the sidecar pattern runs them in two separate containers that are tightly coupled. One container does the main work (the "app"), and the other container runs alongside it to provide a supporting service (the "sidecar" - like a sidecar attached to a motorcycle). Because they are separate, a failure or compromise in one doesn't directly affect the other, and they can have different permission levels.

**Technical:**
In Warden, the AI agent runs in the `jail` container, which is heavily locked down. The Warden network interceptor runs in the `warden-sidecar` container. The crucial link is `network_mode: "service:jail"` in `docker-compose.yml`. This tells Docker to put the sidecar container into the exact same Linux network namespace as the jail container. To the sidecar, the jail's network interfaces are its own network interfaces. The sidecar can configure `iptables` rules that apply to the jail's traffic, because they share the same networking stack, while their filesystems and processes remain completely isolated.

### docker-compose services/networks/volumes
**Part of:** Phase 2 — `docker-compose.yml`
**Why it came up:** Starting the jail and sidecar containers manually with the correct shared namespaces and directory mounts would require complex command-line arguments.

**Plain English:**
Docker Compose is a tool for defining and running multi-container applications. You write a single YAML file (`docker-compose.yml`) that describes all the containers you need, how they should talk to each other, and what files they need access to. When you run `docker-compose up`, it automatically builds the images, creates the virtual networks, and starts the containers with all the correct settings applied.

**Technical:**
- **Services:** Defined under the `services:` key (e.g., `jail`, `warden-sidecar`). A service defines how a container should be built and run.
- **Networks:** Docker creates virtual bridge networks so containers can communicate using IP addresses. In Warden, both containers attach to `warden_bridge`.
- **Volumes:** Containers lose their data when they stop. Volumes map a directory on the host machine (like your Mac) into a directory inside the container. In Warden, `volumes:` maps the `daemon/ledger` directory into the sidecar so it can write to the persistent SQLite database, and maps the `project` directory into the jail so the agent can edit code.

### NFQUEUE and netfilterqueue
**Part of:** Phase 2 — `sidecar/interceptor.py` and `sidecar/Dockerfile`
**Why it came up:** Warden needs to pause outbound network packets, inspect them in Python, and then either drop them or allow them to continue.

**Plain English:**
When a computer sends a network packet, the operating system's firewall rules usually just say "allow" or "block" immediately. NFQUEUE is a special Linux firewall feature that says "pause this packet, hand it over to a userspace program, and wait for that program's decision before sending it." `netfilterqueue` is the Python library that lets our Python script receive those paused packets, read them, and tell the firewall what to do.

**Technical:**
The Linux kernel's `netfilter` subsystem routes packets. The sidecar uses `iptables` to add a rule: `iptables -A OUTPUT -j NFQUEUE --queue-num 0`. This tells the kernel to send all outbound packets to queue number 0. `netfilterqueue` (a C extension wrapping `libnetfilter_queue`) binds to that queue via a Netlink socket. When the agent in the `jail` tries to make a network request, the kernel queues the packet. The Warden Python script receives the raw bytes, inspects them, and calls `packet.accept()` or `packet.drop()`. If dropped, the agent's network connection times out or fails as if the destination is unreachable.

### TLS ClientHello / SNI parsing
**Part of:** Phase 2 — `daemon/parser/packet_parser.py`
**Why it came up:** When the agent makes an HTTPS request (port 443), the traffic is encrypted. We need to know which domain name it's trying to talk to without breaking the encryption.

**Plain English:**
When you connect to a secure website via HTTPS, the very first thing your computer sends is a "Hello" message to start the secure handshake. Because the server needs to know which website's security certificate to send back (since one server might host many sites), this initial Hello message includes the domain name in plain text, even though everything after it will be encrypted. This plain-text domain name is called the SNI (Server Name Indication).

**Technical:**
HTTPS operates over TCP. The initial payload of the TCP connection is the TLS `ClientHello` record. Warden's `PacketParser` manually reads the binary bytes of this payload. It navigates the strict structure defined by RFC 5246: checking the Content Type (0x16 for Handshake), the Handshake Type (0x01 for ClientHello), skipping over random bytes and cipher suites, and locating the Extensions block. It searches for the extension of type 0x0000 (Server Name), extracts the length, and decodes the ASCII bytes of the requested hostname (e.g., `api.openai.com`). This allows Warden to allow or block HTTPS traffic by domain name without performing man-in-the-middle decryption.

### Stateless SNI filtering limits
**Part of:** Phase 2 — `daemon/inspectors/network_inspector.py`
**Why it came up:** HTTPS requests to `api.openai.com` timed out even though the hostname was allowed in `policy.yaml`.

**Plain English:**
When a computer wants to make a secure HTTPS connection, the very first packet it sends is a simple TCP "SYN" packet just to establish the connection line. This first packet contains no data, which means it doesn't contain the SNI (the website name). Because Warden's firewall is "default-deny" (block everything unless explicitly allowed), it looks at this empty SYN packet, sees no allowed website name, and blocks it immediately. The connection is killed before the computer ever gets a chance to send the actual packet containing the SNI. This is why a stateless firewall (one that looks at packets individually without remembering the state of the connection) cannot easily do default-deny hostname filtering.

**Technical:**
The TLS `ClientHello` (which contains the SNI extension) is only sent *after* the 3-way TCP handshake (SYN, SYN-ACK, ACK) completes. Because `NetworkInspector` evaluates each packet in isolation, the initial SYN packet has `hostname_or_sni = None`. Since no rule matches `None` (and it doesn't match the `api.openai.com` hostname rule), it falls through to the `default_action` (BLOCK). To fix this robustly, a firewall must be "stateful" (e.g. using Linux `conntrack`), allowing the TCP handshake to complete and only dropping the connection if the subsequent `ClientHello` contains an unauthorized SNI. For Phase 2's stateless demo, we had to rely on IP-based allowlists instead.

---

### Parse-Time vs Execution-Time Path Resolution in Chained Commands
**Phase:** Daemon Core / Shell Emulation. **Why it came up:** `cd project && echo hello > test.py` was writing test.py to the wrong directory.

**Plain English:** When a shell sees `cd project && echo hello > test.py`, it runs `cd` first, changes its internal directory, and THEN interprets `echo hello > test.py` — resolving `test.py` relative to the new directory. Warden's daemon was parsing the ENTIRE chain into structured objects upfront in one pass. All path resolution (including redirect targets) happened against the *initial* working directory, before any `cd` took effect. By the time the `cd` updated the daemon's state, the `echo`'s redirect path had already been baked into its ParsedAction with the wrong absolute path.

**Technical:** `process()` called `self._parser.parse(raw_command)` which returned a list of `ParsedAction` objects with all `redirect_target` and `target_paths` already resolved via `_resolve_path()` against `self.work_dir`. The `cd` handler updated `self._parser.work_dir`, but the ParsedActions were already created. Fix: split the raw command on operators first (`_split_on_operators()` — a cheap string operation that doesn't resolve paths), then re-parse each individual segment right before executing it, so the parser's `work_dir` reflects any preceding `cd`.

---

### Warden as a Shell Feature Emulator (cd, >, >>)
**Phase:** Daemon Core / Executor. **Why it came up:** `cd` and output redirection are shell built-ins, not real executables, so they cannot work with `subprocess.run(shell=False)`.

**Plain English:** In a real shell, `cd` and `>` are implemented by the shell process itself, not by external programs. When Warden runs commands with `shell=False` (to prevent injection attacks), there is no shell process — the OS tries to find a binary named `cd` in `$PATH` (which doesn't exist) and treats `>` as a literal string argument. Warden must emulate these shell features itself: `cd` becomes a pure Python state update (`self._work_dir = resolved_path`), and `>` becomes Python file I/O (capture subprocess stdout, write to target file with `open()`).

**Technical:** `cd` is intercepted in `_process_single()` before the executor is selected — if the verdict is ALLOW, the daemon resolves the target path, checks `resolved.exists() and resolved.is_dir()`, updates `_work_dir`/`_parser.work_dir`/`_real_executor._work_dir`, and fabricates an `ExecutionResult(exit_code=0)`. Redirection is handled by the parser extracting `redirect_target`/`redirect_append` fields from the token list, and then the executor running the command normally, capturing stdout, and writing it to the target path using Python `open()`. Both features are subject to normal policy evaluation — `redirect_target` is added to `target_paths` so the CommandInspector validates it against path_scope rules.

---

## Phase 3 — The Smart Policy Loop

### The Smart Policy Loop (Data Flow & Design)
**Part of:** Phase 3 — Core Pipeline
**Why it came up:** We needed a way for Warden to learn from the agent's blocked behavior and suggest new rules, without risking a rogue AI automatically breaking its own security sandbox.

**Plain English:** 
Phase 3 acts as an analyst, not an enforcer. Unlike Phase 1 and 2 (which actively block dangerous commands or network packets in real time), Phase 3 never blocks anything live. Instead, it reads the historical ledger after the fact, looks for repeated patterns of blocked behavior, and proposes new rules. A human must approve these proposed rules before they become live policy. The data flows through four steps: 1) the scanner counts repeated flags, 2) the template engine writes an explanation using real numbers instead of AI-generated text, 3) the replayer checks how many past events the new rule would have changed, and 4) the proposal waits in a "waiting room" for human approval. We designed it with "asymmetric scrutiny": it's fast and easy for the system to suggest *blocking* something new, but we are very strict about suggesting *allowing* something new. We also learned that grouping data correctly is critical: if we group network events by the program that sent them (which we often don't know) instead of just the destination, or if we mix up IP addresses and domain names, the scanner misses obvious patterns (two bugs we had to fix).

**Technical:**
The Phase 3 pipeline consists of four main components in data-flow order:
1. `detection_scanner.py`: Scans the `events` table for repeated `FLAG` verdicts crossing a threshold (e.g., N=10 within 6 hours). It uses plain SQL `GROUP BY` queries instead of ML or LLMs to ensure every detection is deterministic and perfectly auditable. Correct grouping is vital: we had to fix two bugs here by splitting `dst_ip` and `hostname_or_sni` into completely independent axes, and applying asymmetric grouping where `shell_command` events group by `(binary, destination)` but `network` events group by `destination` alone.
2. `template_engine.py`: Takes the numerical results from the scanner and fills a fixed string template (e.g., "The pattern crossed the threshold {N} times"). We deliberately avoid using an LLM to invent reasoning text, eliminating hallucination risk.
3. `dry_run_replay.py`: Takes the candidate rule and replays it against the historical ledger events to calculate exact "A-of-B" impact metrics (e.g., "This rule would have changed 12 out of 15 past events").
4. `proposed_rules` table: An SQLite table acting as a pending-approval waiting room. No rule stored here is live policy; the daemon core ignores this table entirely during real-time enforcement. The CLI or dashboard reads from here to present the proposals to the human administrator.

---

## Phase 4 — (not started)

### Phase 2/3 (Ledger Correlation) — SQLite WAL Mode Limitations Across macOS/Docker Boundaries

**Context:** The daemon (running on the Mac host) and the sidecar (running inside a Linux Docker container) both write to the same `warden.db` SQLite file using WAL (Write-Ahead Logging) mode, mapped via a Docker bind-mount.

**Plain English:**
SQLite is usually great at letting multiple programs write to the same database file at the same time. It does this using a special "Write-Ahead Log" (WAL) and a temporary shared memory file (ending in `-shm`) to keep track of who is doing what. However, when you use Docker on a Mac, the Mac host and the Linux container inside Docker are running two completely different operating systems. The software that connects their files (virtiofs or osxfs) cannot share memory between them. Because the shared memory file doesn't sync correctly across the Mac-to-Docker boundary, the two programs get confused. One might write data, and the other might not see it, or they might overwrite each other's work without realizing it.

**Technical:**
SQLite WAL mode relies on `mmap` of the `-shm` (shared memory) index file to manage lock states and WAL index pointers between concurrent database connections. When a database is accessed across an OS boundary via a virtualization filesystem (like Docker Desktop for Mac's `virtiofs` or `osxfs` bind-mounts), `mmap` coherency is not maintained between the macOS host kernel and the Linux VM kernel. 

As a result, a host process and a containerized process opening the same bind-mounted WAL database will instantiate independent, desynchronized `-shm` states. This leads to split-brain behavior where each side can successfully write to the `.db` and `.db-wal` files, but queries from one side will fail to reflect writes committed by the other side. This is an environment limitation of macOS Docker development, not a bug in the application logic. Deployments where all writers are on the same kernel (e.g., native Linux host, or both processes inside containers) do not suffer from this limitation.

### NFQUEUE Intercepting Its Own IPC Traffic
**Part of:** Phase 2 — `sidecar/interceptor.py`
**Why it came up:** When we migrated the sidecar's IPC from Unix domain sockets to a UDP socket, the sidecar stopped being able to send its network events back to the daemon on the host.

**Plain English:** 
The Warden sidecar uses a Linux feature called `NFQUEUE` and `iptables` to catch every network packet leaving the container so it can be inspected. This works perfectly for catching the agent's web traffic. However, when the sidecar finishes inspecting a packet, it needs to send a message back to the daemon on the host to log what happened. Because we switched this message to use UDP, the message itself is a network packet leaving the container. The `iptables` rule caught the sidecar's *own* message, tried to inspect it as web traffic, failed, and dropped it. The sidecar was stuck in an infinite loop of dropping its own reports.

**Technical:** 
The sidecar's iptables rule `iptables -I OUTPUT -j NFQUEUE --queue-num 0` intercepts all outbound IP traffic from the shared network namespace. When IPC was handled via `AF_UNIX` sockets (Phase 1), the IPC traffic did not traverse the IP stack or the `OUTPUT` chain, so it bypassed the queue. When IPC was moved to UDP (Phase 2), the sidecar's `sendto(host.docker.internal:5005)` system calls generated UDP packets traversing the `OUTPUT` chain, causing them to loop back into the same `NFQUEUE`. The `PacketParser` failed to parse them as HTTP/DNS and they were dropped. To fix this, an explicit exemption rule must be inserted at the top of the chain: `iptables -I OUTPUT -p udp --dport 5005 -j ACCEPT`.

---

### Post-Hoc Binary Correlation (Action ID)
**Part of:** Phase 3 — `daemon/advisor/detection_scanner.py`
**Why it came up:** We needed to display which binary (like `curl`) caused a blocked network request when proposing new rules, but network packets themselves don't carry binary names.

**Plain English:** 
When the agent types `curl evil.com`, two things happen: first, a shell command event is logged. Second, a network packet hits the firewall, and a network event is logged. The network packet only contains IP addresses and ports—it has absolutely no idea that `curl` was the program that sent it. To figure out what program caused the network request, we have to match the two events together after the fact. Since both events were linked by a unique ID (`action_id`) when the daemon generated them, we can use that ID to trace the anonymous network packet back to the shell command that started it. Note: I should have logged this automatically when implementing the fix per the Hard Rules, but failed to do so—a process gap I am acknowledging now!

**Technical:** 
In `_resolve_network_binary`, we use a SQL `JOIN` on the `action_id` column to correlate the `network` event with its originating `shell_command` event. This differs from the real-time UDP IPC correlation from the earlier Phase 2 fix (which unified the physical ledgers). Here, we are performing *post-hoc* correlation at scan time: the `events` table contains the linked `action_id` in both rows, allowing the scanner to look up `json_extract(e2.parsed_action, '$.binary')` on a best-effort basis for display purposes only, without altering the pure-destination grouping used for threshold detection.

---

### Docker Bind-Mount vs Tmpfs Semantics
**Part of:** Phase 5 — `DockerJailExecutor`
**Why it came up:** While diagnosing the directory-persistence backlog item, we had to determine why some directory changes inside the jail persisted while others threw errors or disappeared.

**Plain English:**
When a Docker container runs, it usually starts fresh and loses any files you created once it stops. To save files permanently, we map a folder from the host computer directly into the container—this is called a "bind-mount." In Warden, the host's `project/` folder is mapped to `/workspace` inside the container. Anything written to `/workspace` actually saves on the host and persists across restarts. However, the `/tmp` folder in the container is configured as a "tmpfs" (a temporary, in-memory filesystem) for security. Because `/tmp` is not mapped to the host, it cannot be translated back to a host path, and any files put there vanish immediately when the container stops.

**Technical:**
The jail container is explicitly run with `--read-only` and `--tmpfs /tmp`, combined with a `-v ./project:/workspace` bind-mount. This creates two distinct filesystem scopes within the container. When `DockerJailExecutor` translates paths via `_get_container_workdir()`, paths under `./project` correctly resolve into `/workspace/...` and are persisted to the host filesystem. Paths targeting `/tmp` fall entirely outside the host bind-mount. Attempting to translate a daemon-side `work_dir` to `/tmp` fails because there is no corresponding host-side directory to anchor it to; the state is strictly ephemeral and confined to the container's RAM.

---

### Path-Scope Enforcement using pathlib.relative_to()
**Part of:** Phase 5 — `DockerJailExecutor._get_container_workdir()`
**Why it came up:** We discovered a bug where the executor was silently defaulting to `/workspace` for paths that were completely outside the allowed project directory.

**Plain English:**
To translate a folder path on the host computer into the correct folder path inside the Docker container, we need to check if the path is actually inside the allowed `project` folder. Previously, the code just looked at the first word of the path, which meant a path like `/tmp` on the host would get ignored and the container would quietly run the command in the default folder instead. By using `pathlib.relative_to()`, Python mathematically ensures the path is strictly inside the target folder, and raises a loud error if it isn't, preventing commands from silently running in the wrong place.

**Technical:**
A naive string-prefix or list-index check (e.g., `rel_path.parts[0] == "project"`) is vulnerable to path traversal or absolute paths that bypass the prefix entirely. When a path fell outside this check, the previous implementation silently returned the fallback `/workspace`. By switching to `host_path.relative_to(host_repo_root / "project")`, we leverage Python's strict path resolution. If `host_path` is not a true descendant of the project root, `ValueError` is raised. We catch this and re-raise it as a typed `WorkdirOutOfScopeError`, making the path translation failure explicit in the execution result rather than silently altering the command's context.

---

### UDP IPC pending_actions Correlation Model
**Part of:** Phase 2 / Phase 3 Integration — `daemon/ledger/logger.py` & `daemon/core.py`
**Why it came up:** We needed to link a network packet intercepted by the sidecar back to the specific shell command (in the daemon) that caused it, but they run in isolated namespaces.

**Plain English:**
When an AI agent runs a command that talks to the internet, we want our logs to show exactly which command caused which network request. However, the firewall sidecar intercepting the network packet has no idea what shell command is running. Because the sidecar and the main daemon run in completely isolated environments, they can't just share memory or look at each other's processes. To fix this, right before the daemon runs a command, it writes an "I am about to run this" note to the database with a unique ID and a timestamp. When the sidecar sees a network packet, it sends the packet's timestamp over a UDP message to the daemon. The daemon looks at the time, finds the matching "about to run" note, and uses the unique ID to link them together permanently.

**Technical:**
The daemon and sidecar run in separate Docker PID namespaces, making correlation via `/proc/<pid>/environ` or conntrack PID metadata impossible. To bridge this "Correlation Gap", the daemon adopts a single-writer architecture with temporal correlation. Before `subprocess.Popen` executes, the daemon inserts a row into the `pending_actions` SQLite table containing a generated `action_id` and `dispatched_at` timestamp. When the sidecar's NFQUEUE intercepts a packet, it captures the current time and sends a JSON payload containing the packet details and `packet_timestamp` to the daemon via UDP datagram. The daemon's IPC listener receives this, queries `pending_actions` for the closest `dispatched_at` within a strict TTL window (e.g., ±5 seconds), extracts the `action_id`, and tags the network `LedgerEvent`. This successfully unifies the causal chain despite absolute process isolation.

- **Unix Socket Switchboard (Phase 5 Part 1):** Came up while implementing the control plane socket. By intercepting connections on `/tmp/warden_ipc/warden_control.sock`, the daemon accepts requests specifying which `executor` to use (`host` or `docker_jail`). The socket listener temporarily overrides `daemon._real_executor` before injecting the request into the standard `daemon.process(cmd)` pipeline. This ensures both container-bound actions and host-bound actions pass through the exact same shell parsing, command inspection, and rule evaluation layer without code duplication.

### Live Interaction via Control Socket
**Part of:** Phase 5 Part 1 — `warden exec` CLI and `ControlSocket`
**Why it came up:** We manually tested the newly built daemon control socket to confirm it behaves correctly under real conditions before deciding what to build next.

**Plain English:**
When we type commands into the new `warden exec` tool, we saw exactly how the system reacts in the real world. First, commands that are 'FLAGGED' (suspicious but not outright blocked) are currently swallowed silently just like fully blocked commands; they pretend to succeed but do nothing. Second, if we type a broken command (like missing a closing quote), the parser doesn't crash; it just reads what it can, decides it doesn't match a safe rule, and quietly flags it. Third, we proved the network firewall works: when we made an allowed network request, we got a real error message back from the internet (Cloudflare), proving the packet actually left our jail. When we made a blocked request, it just hung until it timed out, proving our firewall silently dropped it without telling the program. Finally, if the daemon is turned off, the CLI tool fails instantly with a clear 'Connection refused' error instead of hanging forever waiting for a response.

**Technical:**
1) The `default_action: flag` rule routes to `FakeExecutor` in `_select_executor()`, meaning FLAG and BLOCK are indistinguishable at execution time (by design, until Phase 3). 2) `shlex.split` does not raise a `ValueError` for unclosed quotes in our configuration; it parses partial tokens. Because those tokens don't match `./project/**`, they fall through to the default FLAG rule. 3) Network ALLOW yields an HTTP 403 (from the remote server), whereas network BLOCK (via NFQUEUE dropping the packet) yields a `TimeoutError` in Python because the TCP SYN packet is blackholed. 4) The `warden exec` CLI handles offline daemons gracefully because `socket.connect()` instantly raises `[Errno 61] Connection refused` when the Unix domain socket lacks a listener process.
