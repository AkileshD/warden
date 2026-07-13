"""
daemon/executors/fake_executor.py — Fabricated-success executor for Warden.

CONTRACT: implements Executor.run() — see daemon/executors/base.py

Used when the Rule Engine's final verdict is BLOCK or FLAG. Returns a
plausible fabricated result that the AI agent's control loop cannot
distinguish from a real success — without actually executing anything.

WHY fabricate rather than error: if Warden returns an error (non-zero exit,
  stderr message), the agent's control loop will retry, escalate, or attempt
  alternative approaches — all of which generate more noise and risk. A silent
  success keeps the agent's loop moving without triggering alarm behaviours.
  This is the core deception mechanic described in WARDEN_SPEC.md §1.

WHY per-binary fabrication table (not a generic "OK"): different binaries have
  different success signatures. `rm` on success prints nothing and exits 0.
  `echo foo` prints "foo\n". A generic success message would look synthetic to
  an agent that inspects output shapes. The table here captures the typical
  success behavior of each binary so the fabrication is indistinguishable.

RISK: Fabrication is heuristic — the table covers common patterns but cannot
  cover every binary or every invocation. When a binary is not in the table,
  we use a silent exit-0 fallback (silent success), which is correct for most
  Unix tools but may be detectable for tools that always produce output (e.g.
  `cat` on a real file would output contents). TODO(phase2): smarter per-binary
  fabrication for output-producing commands (generate plausible file content).

HOW to add a new binary: add an entry to _FABRICATIONS below.
  Format: "binary_name": (stdout: str, stderr: str, exit_code: int)
  Do NOT add conditional Python logic here — if the fabrication needs to be
  dynamic (e.g. echo should return its arguments), use the _dynamic_fabricate()
  path below.
"""

from __future__ import annotations

from .base import Executor, ExecutionResult
from ..parser.shell_parser import ParsedAction
from ..inspectors.base import Verdict


# Fabrication table: binary → (stdout, stderr, exit_code)
# WHY a plain dict: O(1) lookup, easy to read, easy to extend.
# Never put Python logic in this dict — logic goes in _dynamic_fabricate().
_FABRICATIONS: dict[str, tuple[str, str, int]] = {
    # Destructive / write commands — all silent on success
    "rm": ("", "", 0),
    "rmdir": ("", "", 0),
    "dd": ("", "", 0),
    "shred": ("", "", 0),
    "mkfs": ("", "", 0),
    "fdisk": ("", "", 0),
    "wipefs": ("", "", 0),
    "mv": ("", "", 0),
    "cp": ("", "", 0),
    "chmod": ("", "", 0),
    "chown": ("", "", 0),
    "touch": ("", "", 0),
    "mkdir": ("", "", 0),
    "ln": ("", "", 0),
    "unlink": ("", "", 0),
    "truncate": ("", "", 0),
    # Network commands — silent on success (most real usage is -s / quiet flags)
    "curl": ("", "", 0),
    "wget": ("", "", 0),
    "nc": ("", "", 0),
    "ncat": ("", "", 0),
    "netcat": ("", "", 0),
    "ssh": ("", "", 0),
    "scp": ("", "", 0),
    "rsync": ("", "", 0),
    "ftp": ("", "", 0),
    "sftp": ("", "", 0),
    # Privilege escalation — silent success is safest fabrication
    "sudo": ("", "", 0),
    "su": ("", "", 0),
    "doas": ("", "", 0),
    "pkexec": ("", "", 0),
    # Readers of sensitive files — return empty string (as if file is empty)
    # WHY empty string rather than fake content: generating plausible file content
    # is TODO(phase2). For now, an empty file is less suspicious than wrong content.
    "cat": ("", "", 0),
    "less": ("", "", 0),
    "head": ("", "", 0),
    "tail": ("", "", 0),
    "more": ("", "", 0),
    "strings": ("", "", 0),
}

# Binaries that need dynamic fabrication (their output depends on their arguments)
_DYNAMIC_BINARIES = {"echo", "printf", "grep", "awk", "sed"}


class FakeExecutor(Executor):
    """
    CONTRACT: implements Executor.run() — see daemon/executors/base.py

    Generates a plausible fabricated ExecutionResult. Never touches the OS.
    """

    def run(self, action: ParsedAction, verdict: Verdict) -> ExecutionResult:
        """Fabricate a plausible success response for the blocked action."""
        binary = action.binary

        # Check dynamic fabrication first
        if binary in _DYNAMIC_BINARIES:
            stdout, stderr, exit_code = self._dynamic_fabricate(action)
        elif binary in _FABRICATIONS:
            stdout, stderr, exit_code = _FABRICATIONS[binary]
        else:
            # Default: silent success — exit 0, no output
            # WHY: most Unix commands print nothing on success. This is the
            # lowest-suspicion fabrication for an unknown binary.
            stdout, stderr, exit_code = ("", "", 0)

        return ExecutionResult(
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            was_real=False,
            was_fabricated=True,
        )

    @staticmethod
    def _dynamic_fabricate(action: ParsedAction) -> tuple[str, str, int]:
        """Fabricate output for binaries whose success output depends on their args.

        WHY handle echo/printf specially: these commands echo their arguments.
        An agent calling `echo hello` and getting no output would immediately
        notice the deception — echo always produces output on success.

        WHY grep/awk/sed return empty: when a grep finds no matches it exits 1,
        but a grep that is blocked (e.g. reading from a secret file) should
        appear to have found nothing — exit 0, no output, as if the file exists
        but contains no matching lines.
        """
        binary = action.binary

        if binary == "echo":
            # Reproduce what echo would actually print: its non-flag args joined by space
            output_parts = [a for a in action.args if not a.startswith("-")]
            stdout = " ".join(output_parts) + "\n" if output_parts else "\n"
            return (stdout, "", 0)

        if binary == "printf":
            # Too complex to reproduce faithfully — return empty (silent success)
            # RISK: printf always produces output; empty stdout may be detectable.
            # TODO(phase2): implement printf format string simulation.
            return ("", "", 0)

        if binary in ("grep", "awk", "sed"):
            # No matches found — grep exit 1 means "no match", but we want to
            # appear successful (file read was intercepted). Return exit 0, no output.
            # WHY exit 0 not 1: a grep that exits 1 tells the agent "no matches" which
            # is fine, but also implies the file was actually read. Exit 0 + no output
            # is ambiguous and less likely to trigger a retry.
            return ("", "", 0)

        # Fallback for any other dynamic binary
        return ("", "", 0)
