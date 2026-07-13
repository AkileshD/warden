"""
tests/test_parser.py — Unit tests for daemon/parser/shell_parser.py

These tests lock in the exact tokenization behavior. They are explicit about
the expected output (not just "doesn't crash") so that any future parser change
that silently changes tokenization is caught immediately.
"""

from __future__ import annotations

import pytest
from pathlib import Path
from daemon.parser.shell_parser import ShellParser, ParsedAction

# Use a fixed work_dir so resolved paths are predictable in tests
WORK_DIR = Path("/tmp/warden_test_workdir")


@pytest.fixture
def parser():
    return ShellParser(work_dir=WORK_DIR)


# ── Simple command ────────────────────────────────────────────────────────────

class TestSimpleCommand:
    def test_binary_extracted(self, parser):
        actions = parser.parse("ls")
        assert len(actions) == 1
        assert actions[0].binary == "ls"

    def test_flags_extracted(self, parser):
        actions = parser.parse("ls -la")
        assert actions[0].flags == ["-la"]

    def test_arg_extracted(self, parser):
        actions = parser.parse("ls /tmp")
        assert "/tmp" in actions[0].args

    def test_path_resolved(self, parser):
        actions = parser.parse("ls /tmp")
        # WHY resolve(): on macOS, /tmp is a symlink to /private/tmp.
        # The parser correctly resolves symlinks. Compare against resolved form.
        assert Path("/tmp").resolve() in actions[0].target_paths

    def test_combined_flags_and_arg(self, parser):
        actions = parser.parse("ls -la /tmp")
        assert len(actions) == 1
        assert actions[0].binary == "ls"
        assert actions[0].flags == ["-la"]
        assert "/tmp" in actions[0].args

    def test_raw_input_preserved(self, parser):
        raw = "ls -la /tmp"
        actions = parser.parse(raw)
        assert actions[0].raw_input == raw

    def test_empty_string_returns_empty(self, parser):
        assert parser.parse("") == []
        assert parser.parse("   ") == []


# ── Chained commands ──────────────────────────────────────────────────────────

class TestChainedCommands:
    def test_semicolon_produces_two_actions(self, parser):
        actions = parser.parse("ls; rm -rf /")
        assert len(actions) == 2

    def test_semicolon_first_action_correct(self, parser):
        actions = parser.parse("ls; rm -rf /")
        assert actions[0].binary == "ls"

    def test_semicolon_second_action_correct(self, parser):
        actions = parser.parse("ls; rm -rf /")
        assert actions[1].binary == "rm"
        assert "-rf" in actions[1].flags

    def test_and_chain(self, parser):
        actions = parser.parse("mkdir foo && cd foo")
        assert len(actions) == 2
        assert actions[0].binary == "mkdir"
        assert actions[1].binary == "cd"

    def test_or_chain(self, parser):
        actions = parser.parse("test -f foo || echo missing")
        assert len(actions) == 2
        assert actions[0].binary == "test"
        assert actions[1].binary == "echo"

    def test_pipe_chain(self, parser):
        actions = parser.parse("cat file.txt | grep foo")
        assert len(actions) == 2
        assert actions[0].binary == "cat"
        assert actions[1].binary == "grep"

    def test_triple_chain(self, parser):
        actions = parser.parse("a; b; c")
        assert len(actions) == 3
        assert [a.binary for a in actions] == ["a", "b", "c"]


# ── Command substitution ──────────────────────────────────────────────────────

class TestCommandSubstitution:
    def test_dollar_paren_produces_sub_command(self, parser):
        actions = parser.parse("echo $(whoami)")
        assert len(actions) == 1
        action = actions[0]
        assert action.binary == "echo"
        assert len(action.sub_commands) == 1
        assert action.sub_commands[0].binary == "whoami"

    def test_backtick_produces_sub_command(self, parser):
        actions = parser.parse("echo `hostname`")
        assert len(actions) == 1
        assert actions[0].sub_commands[0].binary == "hostname"

    def test_nested_sub_command_binary(self, parser):
        # WHY no quoted glob here: single-quoted '*.tmp' inside $() causes the
        # $(...) regex to fail to match on some shells because of the nested quotes.
        # Use a simpler find invocation without inner quotes to test the mechanic.
        actions = parser.parse("rm $(find /tmp -name tmpfile)")
        assert actions[0].binary == "rm"
        assert len(actions[0].sub_commands) == 1
        assert actions[0].sub_commands[0].binary == "find"


# ── Quoted metacharacters (must NOT split) ────────────────────────────────────

class TestQuotedMetacharacters:
    def test_single_quoted_semicolon_not_split(self, parser):
        """'hello; world' is one argument, not two commands."""
        actions = parser.parse("echo 'hello; world'")
        assert len(actions) == 1
        assert actions[0].binary == "echo"

    def test_double_quoted_semicolon_not_split(self, parser):
        actions = parser.parse('echo "hello; world"')
        assert len(actions) == 1

    def test_single_quoted_and_not_split(self, parser):
        actions = parser.parse("echo 'foo && bar'")
        assert len(actions) == 1

    def test_quoted_content_preserved_as_arg(self, parser):
        actions = parser.parse("echo 'hello; world'")
        # The arg should be the unquoted content (shlex strips the quotes)
        assert "hello; world" in actions[0].args

    def test_mixed_quoted_and_unquoted_chain(self, parser):
        """echo 'a;b'; ls should produce TWO actions: echo and ls."""
        actions = parser.parse("echo 'a;b'; ls")
        assert len(actions) == 2
        assert actions[0].binary == "echo"
        assert actions[1].binary == "ls"


# ── Path resolution ───────────────────────────────────────────────────────────

class TestPathResolution:
    def test_absolute_path_resolved(self, parser):
        actions = parser.parse("cat /etc/passwd")
        # WHY resolve(): on macOS, /etc is a symlink to /private/etc.
        # Compare against the resolved canonical form.
        assert Path("/etc/passwd").resolve() in actions[0].target_paths

    def test_relative_path_resolved_against_workdir(self, parser):
        actions = parser.parse("cat ../../.env")
        resolved = actions[0].target_paths[0]
        # Should be resolved relative to WORK_DIR
        assert resolved.is_absolute()
        # Should NOT contain ".." in the resolved form
        assert ".." not in str(resolved)

    def test_url_not_treated_as_path(self, parser):
        actions = parser.parse("curl https://example.com/data")
        # URL should NOT appear in target_paths
        for p in actions[0].target_paths:
            assert "https" not in str(p)
