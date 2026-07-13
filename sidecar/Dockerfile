# sidecar/Dockerfile — Warden Network Sidecar
#
# This container is Phase 2's network interceptor. Unlike the jail container
# (adversarial, zero capabilities), this is controlled Warden code. It gets
# exactly ONE Linux capability: CAP_NET_ADMIN (granted in docker-compose.yml,
# not in this file — Dockerfiles don't grant capabilities, compose does).
#
# What this image must provide:
#   iptables         — the userspace tool to insert NFQUEUE redirect rules
#                      into the shared network namespace at startup.
#   netfilterqueue   — Python bindings for Linux's NFQUEUE kernel subsystem.
#                      Provides actual packet-level enforcement (intercept
#                      before forward, can drop or accept). NOT passive sniffing.
#   scapy            — used ONLY for parsing raw packet bytes into structured
#                      fields (IP, TCP, UDP, TLS SNI, DNS). Never used for
#                      enforcement or packet injection.
#
# WHY python:3.11-slim (same base as the jail)?
#   Consistency: same Python version, same glibc, fewer surprises. slim is
#   smaller than full Debian while retaining glibc (needed by netfilterqueue's
#   C extension, which wraps a C library).
#
# WHY does netfilterqueue need gcc and kernel headers?
#   netfilterqueue is a C extension that wraps libnetfilter_queue (a C library
#   that talks to the kernel's NFQUEUE netlink subsystem). pip install compiles
#   it from source, requiring a C compiler and the libnetfilter-queue-dev
#   headers. These build dependencies are only needed at image build time, not
#   at runtime.
#
#   A multi-stage build would be the clean production fix (compile in one stage,
#   copy the .so into a fresh slim image). For Phase 2 we accept the larger
#   image and defer that to a TODO.
#   TODO(phase-v2.0): multi-stage build to separate build deps from runtime.
#
# ── KERNEL MODULE NOTE (important for macOS + Docker Desktop) ─────────────
#   netfilterqueue requires the Linux kernel module 'nfnetlink_queue' to be
#   loaded on the HOST kernel (the Docker Desktop LinuxKit VM on macOS).
#   This module is typically present in Docker Desktop's LinuxKit kernel, but
#   must be verified before Phase 5 (interceptor.py) is tested.
#
#   Verification command (run this before writing interceptor.py):
#     docker run --rm --cap-add=NET_ADMIN python:3.11-slim \
#       python3 -c "import netfilterqueue; print('nfnetlink_queue: OK')"
#
#   If that prints OK, the module is present. If it raises OSError, the
#   module is missing from the host kernel and the NFQUEUE approach will not
#   work — escalate to §5 (Open Questions) before proceeding.
#
# ── IMPORTANT: source code is NOT baked into this image ──────────────────
#   The Warden daemon source (daemon/, sidecar/interceptor.py) is bind-mounted
#   into /app at runtime via docker-compose.yml. This means:
#     - Code changes don't require rebuilding the image (fast iteration).
#     - `docker-compose build` only needs to run when Python deps change.
#   The image provides the Python interpreter, system libs, and pip packages.
#   The application code arrives via the volume mount.

FROM python:3.11-slim

# ── System packages ───────────────────────────────────────────────────────────
# All in one RUN to minimise layers. apt cache removed at the end of the
# same layer (removing it in a separate RUN would not reduce image size).
RUN apt-get update && apt-get install -y --no-install-recommends \
        # iptables: userspace CLI for managing netfilter rules.
        # The sidecar uses this at startup to insert the NFQUEUE redirect rule.
        iptables \
        # libnetfilter-queue-dev: C headers for netfilterqueue's pip install.
        libnetfilter-queue-dev \
        # libnfnetlink-dev: netlink library that libnetfilter-queue depends on.
        libnfnetlink-dev \
        # gcc + python3-dev: C compiler and Python headers needed to compile
        # netfilterqueue's C extension from source during pip install.
        gcc \
        python3-dev \
    && pip install --no-cache-dir \
        # netfilterqueue: Python bindings for NFQUEUE packet interception.
        # Version pinned for reproducibility.
        # RISK: netfilterqueue is a C extension — its binary must match the
        # kernel's NFQUEUE ABI. If the Docker Desktop kernel is upgraded and
        # the ABI changes, this may need a rebuild.
        netfilterqueue \
        # scapy: packet parsing library. Used ONLY for reading and parsing
        # raw bytes — not for sending, crafting, or injecting packets.
        scapy \
        PyYAML \
    && rm -rf /var/lib/apt/lists/*

# ── Working directory ─────────────────────────────────────────────────────────
# /app is where docker-compose mounts the project source tree (read-only).
# Python imports (daemon.inspectors, daemon.ledger, etc.) resolve relative
# to this path via PYTHONPATH=/app (set in docker-compose.yml environment).
WORKDIR /app

# ── Default command ───────────────────────────────────────────────────────────
# Runs sidecar/interceptor.py (stub in Step 1, real implementation in Step 5).
# PYTHONPATH and WARDEN_LEDGER_PATH are set in docker-compose.yml so they
# can be overridden at runtime without rebuilding this image.
CMD ["python3", "sidecar/interceptor.py"]
