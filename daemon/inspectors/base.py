"""
daemon/inspectors/base.py — Inspector interface and Verdict type for Warden.

CONTRACT: Every inspector implements Inspector.inspect(action: ParsedAction) -> Verdict.
  - Inspectors are stateless per-call: no side effects, no writes.
  - Inspectors do NOT make the final ALLOW/BLOCK/FLAG decision — that is the
    Rule Engine's job. An inspector returns its *opinion*, which the Rule Engine
    synthesises with policy into a final verdict.
  - Adding a new inspector = writing a class that inherits Inspector, implementing
    inspect(), and registering it in WardenDaemon's inspector list. Nothing else changes.

WHY enum for Decision (not string constants): typos in string comparisons are
  a common source of silent bugs. An enum makes illegal states unrepresentable
  and gives exhaustive checking in match/if-elif chains.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from daemon.parser.shell_parser import ParsedAction


class Decision(Enum):
    """The three possible verdicts an inspector or the Rule Engine can emit."""

    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    FLAG = "FLAG"  # Uncertain / needs review — treated as BLOCK until Phase 3


@dataclass
class Verdict:
    """
    CONTRACT: The output of Inspector.inspect() and the Rule Engine's final decision.

    Fields:
      decision        — ALLOW, BLOCK, or FLAG
      reason          — Human-readable explanation (logged verbatim to ledger)
      source_inspector— Name of the inspector that produced this verdict, for tracing
      confidence      — Optional 0.0–1.0; unused in Phase 1, reserved for Phase 3 AI loop

    WHY include source_inspector: when multiple inspectors run in a chain and the
    Rule Engine synthesises their output, the ledger needs to show *which inspector*
    flagged a command — not just that it was flagged. Grep-ability.
    """

    decision: Decision
    reason: str
    source_inspector: str
    confidence: Optional[float] = None  # TODO(phase3): used by advisory AI loop


@dataclass
class Inspector(ABC):
    """
    CONTRACT: Abstract base class for all Warden inspectors.

    Every inspector must implement inspect() and nothing else is required.
    The core loop (daemon/core.py) calls each inspector's inspect() in order
    and collects the verdicts; it never calls any other method.
    """

    @abstractmethod
    def inspect(self, action: "ParsedAction") -> Optional[Verdict]:
        """Inspect a parsed action and return a verdict, or None if no opinion.

        CONTRACT: Must be pure — no writes, no side effects, no IO.
        """
        ...
