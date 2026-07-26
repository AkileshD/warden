"""
daemon/advisor/dry_run_replay.py — Historical verdict replay for Phase 3.

Given a DetectionCandidate and a candidate YAML rule string, re-evaluates
all historical ledger events for that (binary, destination) pair through
a fresh NetworkInspector with the proposed rule prepended, producing the
"A of B events would have changed verdict" figure.

CONTRACT: policy.yaml is NEVER written to or mutated. The modified rule list
  lives only in memory for the duration of replay(). The original file is
  byte-for-byte unchanged after this function returns. This invariant must
  be preserved unconditionally — it is tested explicitly.

WHY in-memory (not NamedTemporaryFile): RuleEngine.evaluate() aggregates
  inspector verdicts — it does NOT apply network_rules directly. Network rule
  evaluation lives in NetworkInspector. We can instantiate a trial
  NetworkInspector with the proposed rule prepended to the network_rules list,
  entirely in memory, with no disk writes required.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional, TYPE_CHECKING

import yaml

if TYPE_CHECKING:
    from daemon.ledger.logger import Logger
    from daemon.advisor.detection_scanner import DetectionCandidate

from daemon.parser.packet_parser import ParsedNetworkAction
from daemon.inspectors.network_inspector import NetworkInspector


def _deserialise_network_action(parsed_action_json: str) -> Optional[ParsedNetworkAction]:
    """Reconstruct a ParsedNetworkAction from the ledger's stored JSON blob.

    Returns None if the blob cannot be parsed or is not a network event.
    raw_bytes is set to b'' — it is not stored in the ledger and is not
    needed for RuleEngine.evaluate() (which only reads parsed fields).
    """
    try:
        d = json.loads(parsed_action_json)
    except (json.JSONDecodeError, TypeError):
        return None

    # Must have dst_ip to be a network event
    if "dst_ip" not in d:
        return None

    return ParsedNetworkAction(
        binary=d.get("binary", "<network>"),
        args=[],
        flags=[],
        target_paths=[],
        raw_input=d.get("raw_input", ""),
        sub_commands=[],
        dst_ip=d.get("dst_ip", ""),
        dst_port=d.get("dst_port", 0),
        protocol=d.get("protocol", "OTHER"),
        hostname_or_sni=d.get("hostname_or_sni"),
        direction=d.get("direction", "outbound"),
        raw_bytes=b"",
    )


def replay(
    candidate: "DetectionCandidate",
    proposed_yaml_rule: str,
    policy_path: Path,
    logger: "Logger",
) -> tuple[int, int]:
    """Re-evaluate historical events with a proposed rule prepended.

    Args:
      candidate:         The detection that generated this proposed rule.
      proposed_yaml_rule: YAML string for the single candidate rule to prepend.
      policy_path:       Path to the current policy.yaml (read-only).
      logger:            Logger instance (for read_events_for_pair).

    Returns:
      (replay_changed, replay_total) where:
        replay_total   = total events matching (binary, destination)
        replay_changed = events whose verdict WOULD differ with the proposed rule

    CONTRACT: policy.yaml is unchanged after this function returns.
              Never raises — returns (0, 0) on any error.
    """
    try:
        # 1. Load current policy as a dict
        with open(policy_path, "r") as f:
            policy = yaml.safe_load(f)
        if policy is None:
            policy = {}

        # 2. Parse the proposed rule
        proposed_rule = yaml.safe_load(proposed_yaml_rule)

        # 3. Prepend to network_rules (first-match-wins — highest priority).
        #    This is done entirely in memory — policy_path is never opened for writing.
        existing_network_rules = policy.get("network_rules", [])
        trial_network_rules = [proposed_rule] + existing_network_rules

        # 4. Build a NetworkInspector with the trial rule list.
        #    WHY: RuleEngine.evaluate() aggregates inspector verdicts; it does NOT
        #    evaluate network_rules directly. The NetworkInspector is the component
        #    that applies network_rules to ParsedNetworkAction objects.
        #    We instantiate it fresh (no mutation of any live inspector).
        trial_inspector = NetworkInspector(network_rules=trial_network_rules)

        # 5. Fetch historical events for this (binary, destination) pair on the specific axis
        rows = logger.read_events_for_pair(
            candidate.binary, candidate.destination, detection_axis=candidate.detection_axis
        )
        replay_total = len(rows)
        if replay_total == 0:
            return 0, 0

        # 6. Re-evaluate each event through the trial inspector
        replay_changed = 0
        for row in rows:
            parsed = _deserialise_network_action(row.get("parsed_action", "{}"))
            if parsed is None:
                # Not a network event row — skip silently
                continue

            original_verdict = row.get("verdict", "")
            inspector_verdict = trial_inspector.inspect(parsed)
            # NetworkInspector always returns a Verdict (default-deny).
            # If it somehow returned None, treat as FLAG (same as default_action).
            trial_verdict = inspector_verdict.decision.value if inspector_verdict else "FLAG"

            if trial_verdict != original_verdict:
                replay_changed += 1

        return replay_changed, replay_total

    except Exception as e:
        import sys
        print(f"[dry_run_replay] ERROR during replay: {e}", file=sys.stderr)
        return 0, 0
