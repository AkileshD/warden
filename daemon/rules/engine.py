"""
daemon/rules/engine.py — Policy loading and verdict synthesis for Warden.

WHY the Rule Engine is separate from inspectors: inspectors look at one dimension
each (binary, network, rate, etc.) and return an opinion. The Rule Engine owns
the *policy* and makes the final authoritative decision by combining inspector
verdicts with the loaded rules. This separation means policy can change (hot-reload)
without touching any inspector, and new inspectors can be added without touching
policy loading.

CONTRACT: RuleEngine.evaluate(action, inspector_verdicts) -> Verdict
  The returned Verdict is the FINAL decision — the core loop acts on this directly.
  The Rule Engine never modifies the action, never has side effects, never writes.

Rule precedence order (documented here, locked in by tests):
  1. Rules in policy.yaml are evaluated top-down.
  2. First matching rule wins — no scoring, no specificity algorithm.
  3. If no rule matches, `default_action` from policy.yaml applies.
  4. If `default_action` is absent, FLAG is used as a safe fallback.

WHY first-match (not most-specific-match): specificity algorithms (like CSS
selector specificity) are powerful but introduce subtle bugs — two equally-specific
rules can interact in non-obvious ways. First-match is explicit: the rule author
controls precedence by the order they write rules. It's the iptables model.
This decision is documented in WARDEN_BUILD_CONTEXT.md §5 and must not be changed
without updating that file and re-running the precedence tests.

HOW to change policy at runtime: call engine.reload() or send SIGHUP to the
daemon (TODO(phase2): implement SIGHUP handler in core.py). The engine is
thread-safe for reads during a reload because reload() does an atomic swap
of the internal rule list.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any, Optional

import yaml

from ..inspectors.base import Decision, Verdict
from ..parser.shell_parser import ParsedAction


class RuleEngine:
    """
    CONTRACT: RuleEngine.evaluate(action, inspector_verdicts) -> Verdict

    Loads policy.yaml and synthesises a final ALLOW/BLOCK/FLAG verdict
    from the parsed action and any inspector verdicts already collected.

    Thread safety: rules are swapped atomically via a lock during reload().
    Reads (evaluate) acquire a shared read via the same lock to avoid seeing
    a half-updated rule list during a reload.
    """

    def __init__(self, policy_path: Path, work_dir: Optional[Path] = None) -> None:
        self._policy_path = Path(policy_path)
        # WHY store work_dir: policy rules use relative path patterns like
        # "./project/**". When a target path is already resolved to an absolute
        # form (e.g. /Users/user/repo/project/src), we must resolve the pattern
        # against work_dir too so the comparison is apples-to-apples.
        self._work_dir = Path(work_dir).resolve() if work_dir else Path.cwd().resolve()
        self._lock = threading.RLock()
        self._rules: list[dict[str, Any]] = []
        self._default_action: Decision = Decision.FLAG
        self._load()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def rules(self) -> list[dict[str, Any]]:
        """Read-only access to parsed rules — for injecting into inspectors."""
        with self._lock:
            return list(self._rules)  # shallow copy — rules are read-only dicts

    def reload(self) -> None:
        """Hot-reload policy.yaml from disk. Atomic swap under lock."""
        self._load()

    def evaluate(
        self,
        action: ParsedAction,
        inspector_verdicts: Optional[list[Verdict]] = None,
    ) -> Verdict:
        """Synthesise a final verdict for this action.

        Algorithm:
          1. Collect verdicts from all inspectors.
          2. If ANY inspector returned BLOCK, final decision is BLOCK.
          3. Else, if ANY inspector returned FLAG, final decision is FLAG.
          4. Else, if ANY inspector returned ALLOW, final decision is ALLOW.
          5. If no inspector returned a verdict (or no inspectors exist),
             apply default_action from policy.yaml.
        """
        with self._lock:
            default = self._default_action

        if not inspector_verdicts:
            return Verdict(
                decision=default,
                reason=f"No inspector produced a verdict; applying default_action={default.value}",
                source_inspector="RuleEngine",
            )

        # 1. Respect BLOCK as a floor
        for v in inspector_verdicts:
            if v and v.decision == Decision.BLOCK:
                return Verdict(
                    decision=Decision.BLOCK,
                    reason=f"Aggregated BLOCK from inspector: {v.reason}",
                    source_inspector="RuleEngine",
                )

        # 2. FLAG takes precedence over ALLOW
        for v in inspector_verdicts:
            if v and v.decision == Decision.FLAG:
                return Verdict(
                    decision=Decision.FLAG,
                    reason=f"Aggregated FLAG from inspector: {v.reason}",
                    source_inspector="RuleEngine",
                )

        # 3. ALLOW
        for v in inspector_verdicts:
            if v and v.decision == Decision.ALLOW:
                return Verdict(
                    decision=Decision.ALLOW,
                    reason=f"Aggregated ALLOW from inspector: {v.reason}",
                    source_inspector="RuleEngine",
                )

        # 4. Fallback if inspectors returned None
        return Verdict(
            decision=default,
            reason=f"Inspectors produced no opinion; applying default_action={default.value}",
            source_inspector="RuleEngine",
        )

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def _load(self) -> None:
        """Parse policy.yaml and store rules + default_action under lock."""
        policy_path = self._policy_path
        if not policy_path.exists():
            raise FileNotFoundError(f"policy.yaml not found at {policy_path}")

        with open(policy_path, "r") as f:
            raw = yaml.safe_load(f)

        if not isinstance(raw, dict):
            raise ValueError(f"policy.yaml must be a YAML mapping, got {type(raw)}")

        rules: list[dict[str, Any]] = raw.get("rules", [])
        default_str: str = str(raw.get("default_action", "flag")).upper()
        try:
            default = Decision[default_str]
        except KeyError:
            default = Decision.FLAG

        with self._lock:
            self._rules = rules
            self._default_action = default

