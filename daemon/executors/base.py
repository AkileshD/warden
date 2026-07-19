"""
daemon/executors/base.py — Executor interface and ExecutionResult type for Warden.

CONTRACT: Every executor implements Executor.run(action, verdict) -> ExecutionResult.
  - Executors may have side effects (the real one runs subprocesses; the fake one
    constructs a fabricated response). They are the ONLY components allowed to
    have side effects in the core loop.
  - The core loop selects which executor to call based on the final verdict.
    It never contains executor-specific logic.
  - Adding a new executor type = writing a class that inherits Executor,
    implementing run(), and potentially registering it for new verdict types.
    The core loop does not need to change.

WHY separate real/fake executors rather than a single executor with a flag:
  The two executors have fundamentally different responsibilities — one talks to
  the OS, the other fabricates. Merging them would mean a single class that either
  runs real processes OR generates fake output, which is harder to test and reason
  about independently. Separation also makes it trivial to swap in a new fabrication
  strategy (e.g., a smarter LLM-based fabricator in Phase 3) without touching the
  real executor at all.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from daemon.parser.shell_parser import ParsedAction
    from daemon.inspectors.base import Verdict


@dataclass
class ExecutionResult:
    """
    CONTRACT: The output of Executor.run().

    Fields:
      stdout        — What was returned to the caller as stdout (real or fabricated)
      stderr        — What was returned to the caller as stderr
      exit_code     — Exit code returned to the caller (always 0 for fakes)
      was_real      — True if the command was actually executed on the OS
      was_fabricated— True if the response was constructed by the fake executor
      pid           — Subprocess PID set by RealExecutor after Popen; None everywhere else.
                      Used by core.py to update the pending_actions row for correlation.
    """

    stdout: str
    stderr: str
    exit_code: int
    was_real: bool
    was_fabricated: bool
    pid: Optional[int] = None  # Subprocess PID; set by RealExecutor only. None for fake/cd/error paths.


class Executor(ABC):
    """
    CONTRACT: Abstract base class for all Warden executors.

    The core loop calls run() and receives an ExecutionResult.
    It never calls any other method on the executor.
    """

    @abstractmethod
    def run(
        self,
        action: "ParsedAction",  # noqa: F821 (forward ref)
        verdict: "Verdict",  # noqa: F821 (forward ref)
    ) -> ExecutionResult:
        """Execute or fabricate a response for the given action.

        CONTRACT: Must always return an ExecutionResult (never None, never raise
        except on unrecoverable internal errors). A real executor may capture
        subprocess errors inside ExecutionResult; it must not propagate them.
        """
        ...
