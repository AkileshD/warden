"""
daemon/executors/real_executor.py — Real subprocess executor for Warden.

CONTRACT: implements Executor.run() — see daemon/executors/base.py

Wraps subprocess.run() to execute the given ParsedAction on the real OS.
Used only when the Rule Engine's final verdict is ALLOW.

RISK: This executor has real OS side effects. It must ONLY be called after
  the Rule Engine has returned ALLOW. The core loop enforces this — but if the
  core loop ever calls this on a BLOCK verdict, real damage can occur.
  This is noted here so any future refactor of core.py treats the executor
  selection branch as a security-critical path.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Optional

from .base import Executor, ExecutionResult
from ..parser.shell_parser import ParsedAction
from ..inspectors.base import Verdict


class RealExecutor(Executor):
    """
    CONTRACT: implements Executor.run() — see daemon/executors/base.py

    Executes the command via subprocess and returns real stdout/stderr/exit_code.

    WHY re-assemble from ParsedAction rather than using raw_input: using the
    parsed binary + args avoids re-introducing shell metacharacters. The daemon
    has already split chained commands into individual ParsedActions; running
    raw_input for a single action would be safe in most cases, but using the
    structured form is more principled and avoids subtle escaping issues.

    WHY shell=False: running with shell=True reintroduces all the injection risks
    Warden is designed to detect. We always execute the parsed binary directly.
    TODO(phase2): environment sanitization (strip secrets from env vars).
    """

    def __init__(self, work_dir: Optional[Path] = None) -> None:
        # WHY store work_dir: passed as cwd to subprocess so that relative paths
        # in commands (e.g. "ls ./project/") resolve correctly regardless of which
        # directory the daemon process itself was launched from.
        self._work_dir = Path(work_dir) if work_dir else None

    def run(self, action: ParsedAction, verdict: Verdict) -> ExecutionResult:
        """Execute action on the real OS and return its output."""
        # WHY flags before args: POSIX convention; most binaries expect options
        # before positional arguments (some are strict about this).
        cmd = [action.binary] + action.flags + action.args

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,  # TODO(phase2): make timeout configurable in policy.yaml
                cwd=str(self._work_dir) if self._work_dir else None,
            )
            
            if action.redirect_target:
                mode = "a" if action.redirect_append else "w"
                try:
                    with open(action.redirect_target, mode) as f:
                        f.write(result.stdout)
                    # Don't return stdout in the result if it was redirected (matches shell behavior)
                    stdout_result = ""
                except Exception as e:
                    return ExecutionResult(
                        stdout="",
                        stderr=f"warden: failed to write redirection to {action.redirect_target}: {e}",
                        exit_code=1,
                        was_real=True,
                        was_fabricated=False,
                    )
            else:
                stdout_result = result.stdout

            return ExecutionResult(
                stdout=stdout_result,
                stderr=result.stderr,
                exit_code=result.returncode,
                was_real=True,
                was_fabricated=False,
            )
        except FileNotFoundError:
            # Binary not found on PATH
            return ExecutionResult(
                stdout="",
                stderr=f"{action.binary}: command not found",
                exit_code=127,
                was_real=True,
                was_fabricated=False,
            )
        except subprocess.TimeoutExpired:
            return ExecutionResult(
                stdout="",
                stderr=f"{action.binary}: timed out after 30s",
                exit_code=124,
                was_real=True,
                was_fabricated=False,
            )
        except Exception as e:
            return ExecutionResult(
                stdout="",
                stderr=f"warden: internal error running {action.binary!r}: {e}",
                exit_code=1,
                was_real=True,
                was_fabricated=False,
            )
