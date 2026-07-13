# jail/Dockerfile — Warden Agent Sandbox
#
# This is the "room" in the "room with no doors" model (WARDEN_SPEC §2, §11).
# Warden is the guard inside; Docker is the room itself. Defense in depth:
# if Warden fails, the container still can't touch the host filesystem.
#
# Design principles applied here:
#   1. Read-only root filesystem   — nothing the agent writes survives; there is
#      no persistence unless we explicitly provide a writable bind-mount.
#   2. Dropped Linux capabilities  — by default Docker containers run with a
#      large set of Linux capabilities (things like NET_RAW, SYS_PTRACE, etc.).
#      We drop ALL of them explicitly, then add back only the handful actually
#      needed for a Python agent to do useful work (no networking caps at all).
#   3. Non-root user               — the agent runs as uid 1000 ("agent"), not
#      root. Even inside the container, root is not available by default.
#   4. No new privileges           — the no-new-privileges seccomp flag means
#      even if a binary inside has setuid bits, they can't be used to escalate.
#   5. Minimal base image          — python:3.11-slim is Debian-slim, giving us
#      Python + pip + basic shell tools, nothing else. We don't install gcc,
#      curl, wget, or anything an agent could use as an exfiltration vector.
#   6. /tmp writable tmpfs         — completely in-memory, size-capped, never
#      reaches the host disk. Needed so Python can write .pyc cache etc.
#   7. /workspace bind-mount       — this is the only "door" in the room, and
#      it's controlled: the host mounts a specific directory read-write. The
#      agent can work inside /workspace; it can't reach anything outside.
#
# WHY python:3.11-slim and not alpine?
#   Alpine uses musl libc, which breaks some Python C-extension packages.
#   slim is smaller than the full Debian image and uses glibc, so packages
#   compiled for standard Linux work without surprises.
#
# TODO(phase2): Once Phase 2 network interception is built, add the Warden
#   daemon binary/socket into this image or as a sidecar compose service.
#   For now the container is purely the jail — Warden is not yet inside it.

# ── Base image ────────────────────────────────────────────────────────────────
FROM python:3.11-slim

# ── System-level setup ────────────────────────────────────────────────────────
# We run apt-get as root during the build phase (this is normal — the build
# runs as root, but the running container will not).
# We remove the apt cache immediately to keep the image lean.
RUN apt-get update && apt-get install -y --no-install-recommends \
        # Basic shell tools the agent may legitimately need
        coreutils \
        # grep, find, etc. — read-only operations
        grep \
        findutils \
    && rm -rf /var/lib/apt/lists/*

# ── Non-root user ─────────────────────────────────────────────────────────────
# Create a user called "agent" with uid/gid 1000. This is the user the
# container process will run as. Even if an attacker exploits the agent,
# they're stuck as an unprivileged user inside the container.
RUN useradd --uid 1000 --gid 100 --no-create-home --shell /bin/bash agent

# ── Workspace directory ───────────────────────────────────────────────────────
# /workspace is where the agent's project files will live. It is created
# by the Dockerfile so the directory exists on the read-only root layer,
# and then overridden at runtime by a host bind-mount (which is writable).
# The agent can only write here, nowhere else.
RUN mkdir -p /workspace && chown 1000:100 /workspace

# ── Writable temp space ────────────────────────────────────────────────────────
# Python needs somewhere to write .pyc bytecode files. /tmp works.
# We'll mount it as a tmpfs (in-memory) at runtime — nothing persists.
RUN mkdir -p /tmp && chmod 1777 /tmp

# ── Working directory ─────────────────────────────────────────────────────────
WORKDIR /workspace

# ── Drop to non-root user ─────────────────────────────────────────────────────
# From this point on, all RUN instructions (and the container's CMD) execute
# as uid 1000. There is no sudo. There is no su. There is no way back to root
# from within the running container.
USER agent

# ── Default command ───────────────────────────────────────────────────────────
# What runs when `docker run` is called without specifying a command.
# For the jail, we default to a shell — in real use this would be the
# agent process or the Warden entry point.
CMD ["/bin/bash"]
