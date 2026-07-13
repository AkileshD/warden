"""
tests/test_rule_engine.py — Unit tests for daemon/rules/engine.py

CRITICAL: these tests explicitly lock in the rule precedence model:
  - Top-down, first-match-wins
  - If a more general rule appears before a more specific one, the general one fires

Any future change to precedence order MUST update these tests first, then update
WARDEN_BUILD_CONTEXT.md §6 with a changelog entry explaining the change and why.
"""

from __future__ import annotations

import os
import tempfile
import pytest
from pathlib import Path

import yaml

from daemon.rules.engine import RuleEngine
from daemon.parser.shell_parser import ShellParser, ParsedAction
from daemon.inspectors.base import Decision, Verdict
from daemon.inspectors.command_inspector import CommandInspector

WORK_DIR = Path("/tmp/warden_engine_test")
parser_inst = ShellParser(work_dir=WORK_DIR)


def make_action(cmd: str) -> ParsedAction:
    actions = parser_inst.parse(cmd)
    assert actions, f"Parser returned empty for {cmd!r}"
    return actions[0]


def write_policy(rules: list, default_action: str = "flag") -> Path:
    """Write a temporary policy.yaml and return its path."""
    policy = {"rules": rules, "default_action": default_action}
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False, prefix="warden_test_policy_"
    )
    yaml.dump(policy, tmp)
    tmp.close()
    return Path(tmp.name)


def eval_with_inspector(engine: RuleEngine, cmd: str):
    """Helper to simulate the core loop: parse -> inspect -> evaluate."""
    action = make_action(cmd)
    inspector = CommandInspector(rules=engine.rules, work_dir=WORK_DIR)
    v = inspector.inspect(action)
    return engine.evaluate(action, [v] if v else [])


@pytest.fixture(autouse=True)
def cleanup_tmpfiles():
    """Remove temp policy files after each test."""
    created = []
    yield created
    for p in created:
        try:
            Path(p).unlink(missing_ok=True)
        except Exception:
            pass


# ── Precedence: first-match-wins ──────────────────────────────────────────────

class TestRulePrecedenceFirstMatchWins:
    """
    These tests EXPLICITLY lock in first-match-wins behaviour.

    If the rule engine ever changes to a different precedence model,
    these tests will fail — that is intentional. Update the tests and
    WARDEN_BUILD_CONTEXT.md §6 together.
    """

    def test_first_rule_fires_over_later_more_specific_rule(self):
        """
        Rule 1: binary=["*"], path_scope=["*"] → block   (general, first)
        Rule 2: binary=["ls"], path_scope=["*"] → allow  (more specific, second)
        Expected: BLOCK (first rule fires, even though rule 2 would allow ls)
        """
        p = write_policy([
            {"match": {"binary": ["*"], "path_scope": ["*"]}, "action": "block", "risk": "high"},
            {"match": {"binary": ["ls"], "path_scope": ["*"]}, "action": "allow", "risk": "low"},
        ])
        engine = RuleEngine(p)
        verdict = eval_with_inspector(engine, "ls /tmp")
        assert verdict.decision == Decision.BLOCK, (
            "First-match-wins: the general BLOCK rule appears before the specific ALLOW rule, "
            "so BLOCK must fire. If this test fails, the precedence model has changed."
        )
        p.unlink(missing_ok=True)

    def test_specific_allow_first_overrides_general_block(self):
        """
        Rule 1: binary=["ls"], path_scope=["*"] → allow  (specific, first)
        Rule 2: binary=["*"], path_scope=["*"] → block   (general, second)
        Expected: ALLOW (first rule matches, general block never reached)
        """
        p = write_policy([
            {"match": {"binary": ["ls"], "path_scope": ["*"]}, "action": "allow", "risk": "low"},
            {"match": {"binary": ["*"], "path_scope": ["*"]}, "action": "block", "risk": "high"},
        ])
        engine = RuleEngine(p)
        verdict = eval_with_inspector(engine, "ls /tmp")
        assert verdict.decision == Decision.ALLOW
        p.unlink(missing_ok=True)

    def test_source_is_rule_engine(self):
        p = write_policy([
            {"match": {"binary": ["ls"], "path_scope": ["*"]}, "action": "allow", "risk": "low"},
        ])
        engine = RuleEngine(p)
        verdict = eval_with_inspector(engine, "ls /tmp")
        assert verdict.source_inspector == "RuleEngine"
        p.unlink(missing_ok=True)


# ── Real policy.yaml behaviour ────────────────────────────────────────────────

class TestRealPolicy:
    """Tests using the actual daemon/rules/policy.yaml."""

    POLICY = Path(__file__).parent.parent / "daemon" / "rules" / "policy.yaml"

    def test_rm_root_is_blocked(self):
        engine = RuleEngine(self.POLICY)
        verdict = eval_with_inspector(engine, "rm -rf /")
        assert verdict.decision == Decision.BLOCK

    def test_cat_dotenv_is_blocked(self):
        engine = RuleEngine(self.POLICY)
        verdict = eval_with_inspector(engine, "cat /home/user/.env")
        assert verdict.decision == Decision.BLOCK

    def test_ls_project_is_allowed(self):
        engine = RuleEngine(self.POLICY)
        project_path = str(WORK_DIR / "project" / "src")
        verdict = eval_with_inspector(engine, f"ls {project_path}")
        assert verdict.decision == Decision.ALLOW

    def test_curl_is_flagged(self):
        engine = RuleEngine(self.POLICY)
        verdict = eval_with_inspector(engine, "curl https://example.com")
        assert verdict.decision == Decision.FLAG

    def test_sudo_is_blocked(self):
        engine = RuleEngine(self.POLICY)
        verdict = eval_with_inspector(engine, "sudo rm -rf /etc")
        assert verdict.decision == Decision.BLOCK

    def test_unknown_command_is_flagged_by_default(self):
        engine = RuleEngine(self.POLICY)
        verdict = eval_with_inspector(engine, "whoami")
        assert verdict.decision == Decision.FLAG

    def test_python_outside_project_is_flagged(self):
        engine = RuleEngine(self.POLICY)
        verdict = eval_with_inspector(engine, "python3 /tmp/evil.py")
        assert verdict.decision == Decision.FLAG  # default_action


# ── Default action ────────────────────────────────────────────────────────────

class TestDefaultAction:
    def test_default_flag_when_no_rules(self):
        p = write_policy([], default_action="flag")
        engine = RuleEngine(p)
        verdict = eval_with_inspector(engine, "whoami")
        assert verdict.decision == Decision.FLAG
        p.unlink(missing_ok=True)

    def test_default_block(self):
        p = write_policy([], default_action="block")
        engine = RuleEngine(p)
        verdict = eval_with_inspector(engine, "ls")
        assert verdict.decision == Decision.BLOCK
        p.unlink(missing_ok=True)

    def test_default_allow(self):
        p = write_policy([], default_action="allow")
        engine = RuleEngine(p)
        verdict = eval_with_inspector(engine, "ls")
        assert verdict.decision == Decision.ALLOW
        p.unlink(missing_ok=True)


# ── Hot reload ────────────────────────────────────────────────────────────────

class TestHotReload:
    def test_reload_picks_up_new_rules(self, tmp_path):
        policy_path = tmp_path / "policy.yaml"

        # Initial: ls → BLOCK
        initial = {"rules": [
            {"match": {"binary": ["ls"], "path_scope": ["*"]}, "action": "block", "risk": "high"}
        ], "default_action": "flag"}
        policy_path.write_text(yaml.dump(initial))
        engine = RuleEngine(policy_path)
        assert eval_with_inspector(engine, "ls /tmp").decision == Decision.BLOCK

        # Reload with: ls → ALLOW
        updated = {"rules": [
            {"match": {"binary": ["ls"], "path_scope": ["*"]}, "action": "allow", "risk": "low"}
        ], "default_action": "flag"}
        policy_path.write_text(yaml.dump(updated))
        engine.reload()
        assert eval_with_inspector(engine, "ls /tmp").decision == Decision.ALLOW

# ── Mock Inspector / Aggregation ──────────────────────────────────────────────

class TestMockInspectorAggregation:
    def test_block_respects_floor_over_allow(self):
        """Verify that RuleEngine final decision respects BLOCK when an inspector emits it."""
        p = write_policy([], default_action="allow")
        engine = RuleEngine(p)
        
        # Suppose CommandInspector says ALLOW, but MockNetworkInspector says BLOCK
        v_allow = Verdict(decision=Decision.ALLOW, reason="Command looks good", source_inspector="Cmd")
        v_block = Verdict(decision=Decision.BLOCK, reason="Network bad", source_inspector="Net")
        
        verdict = engine.evaluate(make_action("ls"), inspector_verdicts=[v_allow, v_block])
        assert verdict.decision == Decision.BLOCK
        assert "Aggregated BLOCK" in verdict.reason

    def test_flag_overrides_allow(self):
        p = write_policy([], default_action="allow")
        engine = RuleEngine(p)
        
        v_allow = Verdict(decision=Decision.ALLOW, reason="Command looks good", source_inspector="Cmd")
        v_flag = Verdict(decision=Decision.FLAG, reason="Network unknown", source_inspector="Net")
        
        verdict = engine.evaluate(make_action("ls"), inspector_verdicts=[v_allow, v_flag])
        assert verdict.decision == Decision.FLAG
        
    def test_fallback_when_no_verdicts(self):
        p = write_policy([], default_action="block")
        engine = RuleEngine(p)
        
        verdict = engine.evaluate(make_action("ls"), inspector_verdicts=[])
        assert verdict.decision == Decision.BLOCK
        assert "no opinion" in verdict.reason or "No inspector produced" in verdict.reason
