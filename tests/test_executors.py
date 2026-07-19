"""
tests/test_executors.py — Unit tests for real/fake executors and the ledger logger.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from daemon.parser.shell_parser import ShellParser
from daemon.inspectors.base import Decision, Verdict
from daemon.executors.real_executor import RealExecutor
from daemon.executors.fake_executor import FakeExecutor
from daemon.ledger.logger import Logger, LedgerEvent
from daemon.rules.engine import RuleEngine

WORK_DIR = Path("/tmp/warden_executor_test")
parser_inst = ShellParser(work_dir=WORK_DIR)
POLICY = Path(__file__).parent.parent / "daemon" / "rules" / "policy.yaml"


def make_verdict(decision: Decision = Decision.BLOCK) -> Verdict:
    return Verdict(decision=decision, reason="test", source_inspector="test")


def make_action(cmd: str):
    actions = parser_inst.parse(cmd)
    assert actions
    return actions[0]


# ── Real Executor ─────────────────────────────────────────────────────────────

class TestRealExecutor:
    def test_echo_produces_real_output(self):
        executor = RealExecutor()
        action = make_action("echo hello")
        result = executor.run(action, make_verdict(Decision.ALLOW))
        assert "hello" in result.stdout
        assert result.exit_code == 0
        assert result.was_real is True
        assert result.was_fabricated is False

    def test_true_exits_zero(self):
        executor = RealExecutor()
        action = make_action("true")
        result = executor.run(action, make_verdict(Decision.ALLOW))
        assert result.exit_code == 0

    def test_false_exits_nonzero(self):
        executor = RealExecutor()
        action = make_action("false")
        result = executor.run(action, make_verdict(Decision.ALLOW))
        assert result.exit_code != 0

    def test_nonexistent_binary_handled(self):
        executor = RealExecutor()
        action = make_action("nonexistent_binary_xyz_123")
        result = executor.run(action, make_verdict(Decision.ALLOW))
        assert result.exit_code == 127
        assert result.was_real is True

    def test_ls_tmp_returns_output(self):
        executor = RealExecutor()
        action = make_action("ls /tmp")
        result = executor.run(action, make_verdict(Decision.ALLOW))
        assert result.exit_code == 0
        assert result.was_real is True


# ── Fake Executor ─────────────────────────────────────────────────────────────

class TestFakeExecutor:
    def test_rm_is_silent_success(self):
        executor = FakeExecutor()
        action = make_action("rm -rf /")
        result = executor.run(action, make_verdict(Decision.BLOCK))
        assert result.stdout == ""
        assert result.stderr == ""
        assert result.exit_code == 0
        assert result.was_real is False
        assert result.was_fabricated is True

    def test_curl_is_silent_success(self):
        executor = FakeExecutor()
        action = make_action("curl https://exfil.com")
        result = executor.run(action, make_verdict(Decision.BLOCK))
        assert result.exit_code == 0
        assert result.was_fabricated is True

    def test_echo_returns_its_argument(self):
        """Echo is dynamic: fake output must match what real echo would print."""
        executor = FakeExecutor()
        action = make_action("echo hello")
        result = executor.run(action, make_verdict(Decision.BLOCK))
        assert "hello" in result.stdout
        assert result.exit_code == 0

    def test_echo_multiple_args(self):
        executor = FakeExecutor()
        action = make_action("echo foo bar baz")
        result = executor.run(action, make_verdict(Decision.BLOCK))
        assert "foo bar baz" in result.stdout

    def test_unknown_binary_gets_silent_success(self):
        executor = FakeExecutor()
        action = make_action("some_unknown_tool --flag arg")
        result = executor.run(action, make_verdict(Decision.BLOCK))
        assert result.exit_code == 0
        assert result.was_fabricated is True

    def test_cat_returns_empty(self):
        executor = FakeExecutor()
        action = make_action("cat /etc/passwd")
        result = executor.run(action, make_verdict(Decision.BLOCK))
        assert result.stdout == ""
        assert result.exit_code == 0

    def test_sudo_is_silent_success(self):
        executor = FakeExecutor()
        action = make_action("sudo rm -rf /")
        result = executor.run(action, make_verdict(Decision.BLOCK))
        assert result.exit_code == 0
        assert result.was_fabricated is True


# ── Logger ────────────────────────────────────────────────────────────────────

class TestLogger:
    def test_record_writes_row(self, tmp_path):
        logger = Logger(tmp_path / "test.db")
        action = make_action("rm -rf /")
        verdict = make_verdict(Decision.BLOCK)
        from daemon.executors.fake_executor import FakeExecutor
        from daemon.executors.base import ExecutionResult

        result = ExecutionResult(stdout="", stderr="", exit_code=0, was_real=False, was_fabricated=True)
        event = LedgerEvent(raw_input="rm -rf /", parsed_action=action, verdict=verdict, result=result)
        logger.record(event)

        rows = logger.read_all()
        assert len(rows) == 1
        assert rows[0]["raw_input"] == "rm -rf /"
        assert rows[0]["verdict"] == "BLOCK"
        assert rows[0]["execution"] == "fake"
        logger.close()

    def test_record_multiple_rows(self, tmp_path):
        logger = Logger(tmp_path / "multi.db")
        from daemon.executors.base import ExecutionResult
        
        cmds = ["rm -rf /", "ls /tmp", "curl https://x.com"]
        for cmd in cmds:
            action = make_action(cmd)
            verdict = make_verdict(Decision.BLOCK)
            result = ExecutionResult("", "", 0, False, True)
            event = LedgerEvent(raw_input=cmd, parsed_action=action, verdict=verdict, result=result)
            logger.record(event)

        rows = logger.read_all()
        assert len(rows) == 3
        logger.close()

    def test_output_stored_as_json(self, tmp_path):
        logger = Logger(tmp_path / "json_test.db")
        action = make_action("rm -rf /")
        verdict = make_verdict(Decision.BLOCK)
        from daemon.executors.base import ExecutionResult

        result = ExecutionResult("some_out", "some_err", 0, False, True)
        event = LedgerEvent(raw_input="rm -rf /", parsed_action=action, verdict=verdict, result=result)
        logger.record(event)

        rows = logger.read_all()
        output = json.loads(rows[0]["output"])
        assert output["stdout"] == "some_out"
        assert output["stderr"] == "some_err"
        assert output["exit_code"] == 0
        logger.close()

    def test_logger_never_raises_on_bad_input(self, tmp_path):
        """Logger must absorb errors — a logging failure must not crash the daemon."""
        logger = Logger(tmp_path / "resilient.db")
        # Close the DB to force an error on write
        logger.close()
        # This should not raise
        from daemon.executors.base import ExecutionResult
        action = make_action("rm /")
        verdict = make_verdict(Decision.BLOCK)
        result = ExecutionResult("", "", 0, False, True)
        event = LedgerEvent(raw_input="rm /", parsed_action=action, verdict=verdict, result=result)
        try:
            logger.record(event)  # Should absorb the error, not raise
        except Exception as e:
            pytest.fail(f"Logger.record() raised an exception: {e}")


# ── End-to-end core loop (smoke test) ────────────────────────────────────────

class TestCoreLoop:
    def test_full_pipeline_safe_command(self, tmp_path):
        from daemon.core import WardenDaemon
        daemon = WardenDaemon(
            policy_path=POLICY,
            ledger_path=tmp_path / "e2e.db",
            work_dir=WORK_DIR,
        )
        result = daemon.process("echo hello")
        assert result.exit_code == 0
        assert len(result.outcomes) == 1
        # echo hello is not in any blocking rule, default=FLAG → fake
        # OR it could be flagged; either way the daemon returns exit 0
        daemon.close()

    def test_full_pipeline_dangerous_command_is_faked(self, tmp_path):
        from daemon.core import WardenDaemon
        daemon = WardenDaemon(
            policy_path=POLICY,
            ledger_path=tmp_path / "e2e_block.db",
            work_dir=WORK_DIR,
        )
        result = daemon.process("rm -rf /")
        assert result.exit_code == 0  # fake success — agent sees exit 0
        assert result.outcomes[0].verdict.decision == Decision.BLOCK
        assert result.outcomes[0].execution_result.was_fabricated is True
        daemon.close()

    def test_full_pipeline_chained_command(self, tmp_path):
        from daemon.core import WardenDaemon
        daemon = WardenDaemon(
            policy_path=POLICY,
            ledger_path=tmp_path / "e2e_chain.db",
            work_dir=WORK_DIR,
        )
        result = daemon.process("echo hello; rm -rf /")
        assert len(result.outcomes) == 2
        assert result.outcomes[0].action.binary == "echo"
        assert result.outcomes[1].action.binary == "rm"
        assert result.outcomes[1].verdict.decision == Decision.BLOCK
        daemon.close()

    def test_full_pipeline_ledger_has_two_rows_for_chain(self, tmp_path):
        from daemon.core import WardenDaemon
        daemon = WardenDaemon(
            policy_path=POLICY,
            ledger_path=tmp_path / "e2e_rows.db",
            work_dir=WORK_DIR,
        )
        daemon.process("echo hello; rm -rf /")
        rows = daemon.read_ledger()
        assert len(rows) == 2
        daemon.close()


# ── Step 3: PID surfacing ─────────────────────────────────────────────────────

class TestRealExecutorPID:
    """Confirm subprocess PID is correctly surfaced through ExecutionResult."""

    def test_pid_is_positive_integer_on_success(self):
        executor = RealExecutor()
        action = make_action("echo hello")
        result = executor.run(action, make_verdict(Decision.ALLOW))
        assert result.pid is not None, "PID should be set on successful real execution"
        assert isinstance(result.pid, int)
        assert result.pid > 0

    def test_pid_not_none_on_redirect(self, tmp_path):
        """PID must be set even when stdout is redirected to a file."""
        target = tmp_path / "out.txt"
        executor = RealExecutor(work_dir=tmp_path)
        action = make_action(f"echo redirected > {target}")
        result = executor.run(action, make_verdict(Decision.ALLOW))
        assert result.pid is not None and result.pid > 0

    def test_pid_is_none_on_file_not_found(self):
        """FileNotFoundError path: no subprocess was started, PID must be None."""
        executor = RealExecutor()
        action = make_action("echo placeholder")
        action.binary = "__no_such_binary__"
        result = executor.run(action, make_verdict(Decision.ALLOW))
        assert result.exit_code == 127
        assert result.pid is None

    def test_pid_is_none_on_fake_executor(self):
        """FakeExecutor never starts a subprocess — PID must always be None."""
        executor = FakeExecutor()
        action = make_action("rm -rf /")
        result = executor.run(action, make_verdict(Decision.BLOCK))
        assert result.pid is None

    def test_exit_code_and_stderr_preserved_on_nonzero(self):
        """Nonzero exit code from real process is preserved exactly as before."""
        executor = RealExecutor()
        action = make_action("ls /nonexistent_path_warden_test_12345")
        result = executor.run(action, make_verdict(Decision.ALLOW))
        assert result.exit_code != 0
        assert result.pid is not None and result.pid > 0

    def test_existing_behavior_stdout_capture(self):
        """stdout is still captured correctly after the Popen refactor."""
        executor = RealExecutor()
        action = make_action("echo popen_works")
        result = executor.run(action, make_verdict(Decision.ALLOW))
        assert "popen_works" in result.stdout
        assert result.exit_code == 0
        assert result.was_real is True
        assert result.was_fabricated is False
