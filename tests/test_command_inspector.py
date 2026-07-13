"""
tests/test_command_inspector.py — Unit tests for daemon/inspectors/command_inspector.py

These tests verify that the CommandInspector correctly evaluates binary names
and target paths against injected rules. They do NOT test policy.yaml loading
(that's the Rule Engine's job). Rules are injected directly.
"""

from __future__ import annotations

import pytest
from pathlib import Path

from daemon.parser.shell_parser import ShellParser, ParsedAction
from daemon.inspectors.base import Decision
from daemon.inspectors.command_inspector import CommandInspector

WORK_DIR = Path("/tmp/warden_inspector_test")
parser = ShellParser(work_dir=WORK_DIR)

# Minimal test rule set — mirrors the shape of policy.yaml but is NOT policy.yaml
TEST_RULES = [
    {
        "match": {
            "binary": ["rm", "dd", "shred"],
            "path_scope": ["!./project/**"],
        },
        "action": "block",
        "risk": "high",
    },
    {
        "match": {
            "binary": ["cat", "less", "head"],
            "path_scope": ["**/.env", "**/*.pem", "**/id_rsa*"],
        },
        "action": "block",
        "risk": "high",
    },
    {
        "match": {
            "binary": ["curl", "wget"],
            "path_scope": ["*"],
        },
        "action": "flag",
        "risk": "medium",
    },
    {
        "match": {
            "binary": ["*"],
            "path_scope": ["./project/**"],
        },
        "action": "allow",
        "risk": "low",
    },
]


@pytest.fixture
def inspector():
    return CommandInspector(rules=TEST_RULES)


def make_action(cmd: str) -> ParsedAction:
    """Parse a command string into a ParsedAction for test input."""
    actions = parser.parse(cmd)
    assert actions, f"Parser returned empty for {cmd!r}"
    return actions[0]


# ── Blocking dangerous binaries ───────────────────────────────────────────────

class TestDestructiveBinaryBlock:
    def test_rm_outside_project_is_blocked(self, inspector):
        action = make_action("rm -rf /etc/hosts")
        verdict = inspector.inspect(action)
        assert verdict.decision == Decision.BLOCK

    def test_dd_is_blocked(self, inspector):
        action = make_action("dd if=/dev/zero of=/dev/sda")
        verdict = inspector.inspect(action)
        assert verdict.decision == Decision.BLOCK

    def test_shred_is_blocked(self, inspector):
        action = make_action("shred /etc/passwd")
        verdict = inspector.inspect(action)
        assert verdict.decision == Decision.BLOCK

    def test_source_inspector_is_labeled(self, inspector):
        action = make_action("rm /etc/hosts")
        verdict = inspector.inspect(action)
        assert verdict.source_inspector == "CommandInspector"

    def test_reason_is_populated(self, inspector):
        action = make_action("rm /etc/hosts")
        verdict = inspector.inspect(action)
        assert verdict.reason and len(verdict.reason) > 0


# ── Blocking credential reads ─────────────────────────────────────────────────

class TestCredentialReadBlock:
    def test_cat_dotenv_is_blocked(self, inspector):
        action = make_action("cat /home/user/project/.env")
        verdict = inspector.inspect(action)
        assert verdict.decision == Decision.BLOCK

    def test_cat_pem_is_blocked(self, inspector):
        action = make_action("cat /etc/ssl/server.pem")
        verdict = inspector.inspect(action)
        assert verdict.decision == Decision.BLOCK

    def test_cat_id_rsa_is_blocked(self, inspector):
        action = make_action("cat /home/user/.ssh/id_rsa")
        verdict = inspector.inspect(action)
        assert verdict.decision == Decision.BLOCK

    def test_head_dotenv_is_blocked(self, inspector):
        action = make_action("head /home/user/.env")
        verdict = inspector.inspect(action)
        assert verdict.decision == Decision.BLOCK


# ── Flagging network commands ─────────────────────────────────────────────────

class TestNetworkFlag:
    def test_curl_is_flagged(self, inspector):
        action = make_action("curl https://example.com")
        verdict = inspector.inspect(action)
        assert verdict.decision == Decision.FLAG

    def test_wget_is_flagged(self, inspector):
        action = make_action("wget https://example.com/file")
        verdict = inspector.inspect(action)
        assert verdict.decision == Decision.FLAG


# ── Allowing safe commands inside project dir ─────────────────────────────────

class TestProjectDirAllow:
    def test_ls_inside_project_is_allowed(self, inspector):
        # Use an absolute path that resolves to under WORK_DIR/project
        project_path = str(WORK_DIR / "project" / "src")
        action = make_action(f"ls {project_path}")
        verdict = inspector.inspect(action)
        assert verdict.decision == Decision.ALLOW

    def test_python_inside_project_is_allowed(self, inspector):
        project_path = str(WORK_DIR / "project" / "main.py")
        action = make_action(f"python3 {project_path}")
        verdict = inspector.inspect(action)
        assert verdict.decision == Decision.ALLOW


# ── Default (no rule matches) ─────────────────────────────────────────────────

class TestDefault:
    def test_unknown_binary_gets_none(self, inspector):
        action = make_action("whoami")
        verdict = inspector.inspect(action)
        # whoami has no target paths and matches no specific rule → None (no opinion)
        assert verdict is None

    def test_env_command_gets_none(self, inspector):
        action = make_action("env")
        verdict = inspector.inspect(action)
        assert verdict is None
