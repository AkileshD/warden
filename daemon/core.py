"""
daemon/core.py — The Warden daemon core loop.

This file wires the five components together:
  Parser → Inspector chain → Rule Engine → Executor → Logger

CONTRACT: This file MUST NOT contain any inspector-specific, executor-specific,
  or policy-specific logic. If you find yourself writing `if binary == "rm"` or
  `if decision == BLOCK and binary == "curl"` here, stop — that logic belongs
  in an inspector, the rule engine, or policy.yaml.

  Adding a new inspector = append to self._inspectors in __init__.
  Adding a new executor type = add a branch in _select_executor().
  That's it. The loop itself (process()) never changes.

WHY the daemon doesn't run as an actual daemon process yet: Phase 1 scope is
  the interception mechanic and ledger, not process management. The `process()`
  method is the public API — it can be called from a REPL, a demo script, a
  test, or eventually a proper daemon entry point.
  TODO(phase2): wrap in a Unix socket server or HTTP API for real agent integration.

WHY all five stages are in one method (process()): the pipeline is sequential
  and the stages are tightly coupled by data flow (each stage needs the previous
  stage's output). Splitting into separate methods would add indirection without
  value. If the pipeline grows (Phase 2 network inspection), new stages append
  to the method — they don't require restructuring existing stages.
"""

from __future__ import annotations

import json
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .parser.shell_parser import ShellParser, ParsedAction
from .inspectors.base import Decision, Inspector, Verdict
from .inspectors.command_inspector import CommandInspector
from .rules.engine import RuleEngine
from .executors.base import Executor, ExecutionResult
from .executors.real_executor import RealExecutor
from .executors.fake_executor import FakeExecutor
from .ledger.logger import Logger, LedgerEvent
from .ipc_listener import IPCListener


@dataclass
class ProcessResult:
    """The complete output of one call to WardenDaemon.process().

    Contains one entry per sub-command found in the raw input
    (e.g. "ls; rm -rf /" → two ActionOutcome objects).
    """

    outcomes: list[ActionOutcome]

    @property
    def stdout(self) -> str:
        """Combined stdout of all sub-commands, in order."""
        return "".join(o.execution_result.stdout for o in self.outcomes)

    @property
    def exit_code(self) -> int:
        """Exit code of the last sub-command (matches shell behaviour)."""
        if self.outcomes:
            return self.outcomes[-1].execution_result.exit_code
        return 0


@dataclass
class ActionOutcome:
    """Result of processing a single ParsedAction through the full pipeline."""

    action: ParsedAction
    verdict: Verdict
    execution_result: ExecutionResult


class WardenDaemon:
    """
    The Warden interception daemon.

    Usage:
        daemon = WardenDaemon(
            policy_path=Path("daemon/rules/policy.yaml"),
            ledger_path=Path("warden.db"),
            work_dir=Path("."),
        )
        result = daemon.process("ls; rm -rf /")
        print(result.stdout)   # agent sees this
        print(result.exit_code)
    """

    def __init__(
        self,
        policy_path: Path,
        ledger_path: Path,
        work_dir: Optional[Path] = None,
        session_id: Optional[str] = None,
        ipc_token_path: Path = Path("ipc_data/token.txt"),
    ) -> None:
        self._work_dir = Path(work_dir) if work_dir else Path.cwd()
        self._session_id = session_id
        self._ipc_token_path = ipc_token_path

        # Component initialisation order matters: Rule Engine must load policy
        # before inspectors are constructed (they receive the parsed rules).
        self._rule_engine = RuleEngine(policy_path, work_dir=self._work_dir)
        self._parser = ShellParser(work_dir=self._work_dir)

        # Inspector chain — ORDER MATTERS: inspectors run in this sequence.
        # The first inspector to register a strong opinion influences the Rule
        # Engine's final call. (Network inspection happens in the sidecar, not here).
        self._inspectors: list[Inspector] = [
            CommandInspector(rules=self._rule_engine.rules, work_dir=self._work_dir),
        ]

        self._real_executor = RealExecutor(work_dir=self._work_dir)
        self._fake_executor = FakeExecutor()
        self._logger = Logger(ledger_path)
        
        # Start the IPC listener for network events from the sidecar
        self._ipc_listener = IPCListener(logger=self._logger, token_path=self._ipc_token_path)
        self._ipc_listener.start()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def process(self, raw_command: str) -> ProcessResult:
        """Intercept, evaluate, execute (real or fake), and log a raw command.

        Returns a ProcessResult that looks identical to what a real shell would
        return — stdout, stderr, and exit_code. The caller (agent) cannot tell
        whether execution was real or fabricated.

        For chained commands (ls; rm -rf /), each sub-command is processed
        independently and in order. Real sub-commands execute; blocked ones
        are faked. The results are combined into a single ProcessResult.

        WHY process sub-commands independently: a chained command like
        "ls; rm -rf /" has two distinct intents. `ls` may be entirely safe;
        `rm -rf /` is catastrophic. Treating the chain as a single unit would
        force an all-or-nothing decision. Processing independently gives correct
        granularity and a cleaner ledger (one row per actual command, not one
        row per raw input containing a chain).

        WHY split-then-reparse (not parse-all-upfront): chained commands like
        "cd ./project && echo hello > test.py" contain path references that
        MUST be resolved relative to the CURRENT work_dir at the time each
        sub-command executes, not the work_dir at parse time. A preceding cd
        changes the daemon's work_dir, so later sub-commands must be re-parsed
        against the updated work_dir. We split on operators first (cheap string
        op), then parse each segment individually right before executing it.
        """
        raw_command = raw_command.strip()
        if not raw_command:
            return ProcessResult(outcomes=[])

        # ── Stage 1: Split on operators ──────────────────────────────
        # Split the raw command into segments on shell operators (; && || |)
        # but do NOT parse them yet — parsing resolves paths, and we need
        # each segment parsed with the work_dir current at execution time.
        segments = self._parser._split_on_operators(raw_command)
        if not segments:
            return ProcessResult(outcomes=[])

        outcomes: list[ActionOutcome] = []

        for segment in segments:
            segment = segment.strip()
            if not segment:
                continue
            # Re-parse this single segment with the CURRENT work_dir
            # (which may have been updated by a preceding cd in this chain)
            actions = self._parser.parse(segment)
            for action in actions:
                outcome = self._process_single(action, raw_command)
                outcomes.append(outcome)

        return ProcessResult(outcomes=outcomes)

    def reload_policy(self) -> None:
        """Hot-reload policy.yaml from disk and refresh inspector rules."""
        self._rule_engine.reload()
        # Rebuild inspectors with the new rule set
        # WHY rebuild rather than update in place: CommandInspector stores a copy
        # of rules at construction. Rebuilding is the safest way to ensure they
        # all see the fresh rule set simultaneously.
        self._inspectors = [
            CommandInspector(rules=self._rule_engine.rules, work_dir=self._work_dir),
        ]

    def close(self) -> None:
        """Clean shutdown — close database connections and stop threads."""
        self._ipc_listener.stop()
        self._logger.close()

    # ------------------------------------------------------------------
    # Internal pipeline
    # ------------------------------------------------------------------

    def _process_single(self, action: ParsedAction, raw_command: str) -> ActionOutcome:
        """Run one ParsedAction through the full pipeline: inspect → decide → execute → log."""

        # ── Stage 2: Inspect ─────────────────────────────────────────
        inspector_verdicts: list[Verdict] = []
        for inspector in self._inspectors:
            v = inspector.inspect(action)
            inspector_verdicts.append(v)

        # ── Stage 3: Rule Engine → final verdict ─────────────────────
        final_verdict = self._rule_engine.evaluate(action, inspector_verdicts)

        # ── Stage 4: Execute (real or fake) ──────────────────────────
        # CONTRACT: this is the ONLY place where executor selection happens.
        # ALLOW → real. BLOCK or FLAG → fake. No exceptions, no special cases.
        action_id = None
        if action.binary == "cd" and final_verdict.decision == Decision.ALLOW:
            # cd is a shell built-in; it cannot be executed by subprocess/docker-compose exec
            # We must handle it as a pure internal state update.
            new_dir_str = action.args[0] if action.args else "~"
            if new_dir_str.startswith("/"):
                resolved = Path(new_dir_str)
            elif new_dir_str == "~":
                resolved = Path.home()
            else:
                resolved = (self._work_dir / new_dir_str).resolve()

            if resolved.exists() and resolved.is_dir():
                self._work_dir = resolved
                self._parser.work_dir = resolved
                self._real_executor._work_dir = resolved
                execution_result = ExecutionResult(
                    stdout="", stderr="", exit_code=0, was_real=True, was_fabricated=False
                )
            else:
                execution_result = ExecutionResult(
                    stdout="", stderr=f"cd: {new_dir_str}: No such file or directory", exit_code=1, was_real=True, was_fabricated=False
                )
        else:
            if final_verdict.decision == Decision.ALLOW:
                action_id = str(uuid.uuid4())
                self._logger.write_pending_action(
                    action_id=action_id,
                    dispatched_at=time.time(),
                    binary=action.binary,
                    args=json.dumps(action.args),
                )

            executor = self._select_executor(final_verdict.decision)
            execution_result = executor.run(action, final_verdict)

            if action_id and execution_result.pid:
                self._logger.update_pending_action_pid(action_id, execution_result.pid)

        # ── Stage 5: Log ─────────────────────────────────────────────
        ledger_event = LedgerEvent(
            raw_input=raw_command,
            parsed_action=action,
            verdict=final_verdict,
            result=execution_result,
            event_type="shell_command",
            session_id=self._session_id,
            risk=self._extract_risk(final_verdict),
            action_id=action_id,
        )
        self._logger.record(ledger_event)

        return ActionOutcome(
            action=action,
            verdict=final_verdict,
            execution_result=execution_result,
        )

    def _select_executor(self, decision: Decision) -> Executor:
        """Map a Decision to the appropriate executor.

        CONTRACT: ALLOW → real. Anything else → fake.
        This is the security boundary. If this mapping changes, it must be
        reviewed carefully — it is what determines whether real OS calls happen.
        """
        if decision == Decision.ALLOW:
            return self._real_executor
        return self._fake_executor

    @staticmethod
    def _extract_risk(verdict: Verdict) -> Optional[str]:
        """Extract risk level from verdict reason string if present."""
        reason = verdict.reason or ""
        for level in ("high", "medium", "low"):
            if f"risk={level}" in reason:
                return level
        return None

    # ------------------------------------------------------------------
    # Convenience: read ledger (for demo/CLI use)
    # ------------------------------------------------------------------

    def read_ledger(self) -> list[dict]:
        """Return all ledger rows. For demo and CLI viewer use only."""
        return self._logger.read_all()
