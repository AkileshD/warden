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

## Phase 3 — (not started)

---

## Phase 4 — (not started)
