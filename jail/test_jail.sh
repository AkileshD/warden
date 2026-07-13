#!/usr/bin/env bash
# jail/test_jail.sh — Prove the container enforces its boundaries.
#
# Run this script AFTER building the image with:
#   docker build -t warden-jail ./jail
#
# Each test prints PASS or FAIL with a reason. All five should pass.
# If any fail, the Dockerfile constraints aren't working as expected.
#
# WHY test this manually rather than in pytest?
#   These aren't unit tests of Python code — they're integration tests
#   of Docker's enforcement layer. They need a live Docker daemon and
#   can't run in CI without one. Keeping them as a separate script
#   makes that dependency explicit.

set -uo pipefail

IMAGE="warden-jail"
PASS=0
FAIL=0

run_test() {
    local name="$1"
    local cmd="$2"
    local expect_success="$3"  # "yes" = exit 0 expected, "no" = nonzero expected

    output=$(eval "$cmd" 2>&1)
    exit_code=$?

    if [[ "$expect_success" == "yes" && $exit_code -eq 0 ]]; then
        echo "  PASS  $name"
        ((PASS++))
    elif [[ "$expect_success" == "no" && $exit_code -ne 0 ]]; then
        echo "  PASS  $name (correctly failed: $output)"
        ((PASS++))
    else
        echo "  FAIL  $name (exit=$exit_code, output=$output)"
        ((FAIL++))
    fi
}

echo ""
echo "war(den) jail verification"
echo "──────────────────────────────────────────────────────"
echo ""

# ── Test 1: Container starts and basic Python works ───────────────────────────
# The simplest possible proof the image built correctly and runs.
run_test "Container starts, Python available" \
    "docker run --rm $IMAGE python3 -c 'print(\"hello from jail\")'" \
    "yes"

# ── Test 2: Running as non-root (uid 1000, not 0) ─────────────────────────────
# Verifies USER agent was applied. If this returns 0, we're running as root
# which defeats the non-root constraint.
run_test "Agent runs as uid 1000 (not root)" \
    "docker run --rm $IMAGE python3 -c 'import os; assert os.getuid() == 1000, f\"got uid {os.getuid()}\"'" \
    "yes"

# ── Test 3: Read-only root filesystem rejects writes ──────────────────────────
# --read-only is the runtime flag that makes the rootfs read-only.
# The agent should NOT be able to write outside /tmp or a bind-mount.
# This write attempt to /etc/evil should fail with "Read-only file system".
run_test "Write to root filesystem fails (read-only enforced)" \
    "docker run --rm --read-only --tmpfs /tmp:size=64m $IMAGE python3 -c 'open(\"/etc/evil\", \"w\").write(\"pwned\")'" \
    "no"

# ── Test 4: Write to /tmp works (tmpfs exemption) ─────────────────────────────
# /tmp is mounted as an in-memory tmpfs — agent can write there (Python needs
# it for .pyc etc.) but it disappears when the container exits.
run_test "Write to /tmp succeeds (tmpfs exemption works)" \
    "docker run --rm --read-only --tmpfs /tmp:size=64m $IMAGE python3 -c 'open(\"/tmp/test.txt\", \"w\").write(\"ok\")'" \
    "yes"

# ── Test 5: Dropped capabilities — no raw socket (NET_RAW) ───────────────────
# --cap-drop=ALL removes all Linux capabilities. Without NET_RAW, creating a
# raw socket (used for ping, port scanners, etc.) fails with EPERM.
# This is the key test: even inside the container, the agent can't do
# low-level network operations that bypass normal socket APIs.
run_test "Raw socket creation blocked (NET_RAW dropped)" \
    "docker run --rm --cap-drop=ALL --security-opt=no-new-privileges $IMAGE python3 -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)'" \
    "no"

echo ""
echo "──────────────────────────────────────────────────────"
echo "  Results: ${PASS} passed, ${FAIL} failed"
echo ""

if [[ $FAIL -gt 0 ]]; then
    exit 1
fi
