#!/usr/bin/env python3
"""
demo/run_phase3_advisor.py — Phase 3 Smart Policy Loop: full pipeline runner.

Orchestrates the complete advisor pipeline as a single manual invocation:
  1. Scan the events table for (binary, destination) pairs crossing N=10/T=6h
  2. For each candidate: dry-run replay → template fill → write proposed_rules row
  3. Print a summary and instructions to run the approval CLI

Usage:
  python demo/run_phase3_advisor.py
  python demo/run_phase3_advisor.py --db warden_demo.db --policy daemon/rules/policy.yaml
  python demo/run_phase3_advisor.py --n 5 --window 12.0   # tune thresholds

WHY a standalone script (not integrated into the daemon process):
  The detection algorithm needs validation against real ledger data before
  being committed to a continuous loop. A manually-invoked script lets us
  observe whether N=10/T=6h generates sensible proposals against real data
  before scheduling it. See WARDEN_SPEC.md §9 and WARDEN_BUILD_CONTEXT.md §4
  for the backlog item covering a scheduled runner.
"""

from __future__ import annotations

import argparse
import sys
import time
import uuid
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Warden Phase 3 advisor — scan ledger and generate policy proposals",
    )
    parser.add_argument("--db", default="warden_demo.db", help="Path to warden SQLite DB")
    parser.add_argument(
        "--policy", default="daemon/rules/policy.yaml", help="Path to policy.yaml"
    )
    parser.add_argument("--n", type=int, default=10, help="FLAG count threshold (default: 10)")
    parser.add_argument(
        "--window", type=float, default=6.0, help="Rolling window in hours (default: 6.0)"
    )
    args = parser.parse_args()

    db_path = Path(args.db)
    policy_path = Path(args.policy)

    if not db_path.exists():
        print(f"Error: database not found at {db_path}", file=sys.stderr)
        print("Run a demo session first to generate ledger data.", file=sys.stderr)
        return 1

    if not policy_path.exists():
        print(f"Error: policy.yaml not found at {policy_path}", file=sys.stderr)
        return 1

    # Import here so PYTHONPATH doesn't need to be set at the top of the file
    from daemon.ledger.logger import Logger, ProposedRule
    from daemon.advisor.detection_scanner import scan
    from daemon.advisor.dry_run_replay import replay
    from daemon.advisor.template_engine import (
        build_proposed_rule,
        build_reasoning_text,
        is_permissive,
    )

    print("=" * 60)
    print("Warden Phase 3 Advisor — Policy Proposal Scanner")
    print("=" * 60)
    print(f"Database:   {db_path.resolve()}")
    print(f"Policy:     {policy_path.resolve()}")
    print(f"Threshold:  N={args.n} FLAGs within T={args.window:.0f}h rolling window")
    print()

    logger = Logger(db_path)

    # Step 1: Detect
    print("Step 1/3: Scanning for patterns...")
    candidates = scan(logger, n_threshold=args.n, window_hours=args.window)
    print(f"  Found {len(candidates)} candidate(s) crossing the threshold.")
    print()

    if not candidates:
        print("No candidates found.")
        print()
        print(
            f"This means no (binary, destination) pair received >= {args.n} FLAG verdicts\n"
            f"for network events within the last {args.window:.0f} hours of ledger data."
        )
        print()
        print(
            "If the real ledger has fewer than N FLAG network events per destination,\n"
            "N may need tuning. Re-run with --n <lower value> to experiment.\n"
            "Document the finding before changing the default — see WARDEN_SPEC.md §9."
        )
        logger.close()
        return 0

    # Steps 2–3: Replay + template fill + write proposals
    print("Step 2/3: Running dry-run replay and filling proposal templates...")
    proposals_written = 0

    for i, candidate in enumerate(candidates, 1):
        print(f"  Candidate {i}/{len(candidates)}: {candidate.binary} → {candidate.destination} "
              f"({candidate.occurrence_count} FLAGs)")

        # Build proposed YAML rule
        proposed_yaml = build_proposed_rule(candidate)

        # Dry-run replay
        replay_changed, replay_total = replay(candidate, proposed_yaml, policy_path, logger)
        print(f"    Replay: {replay_changed} of {replay_total} events would change verdict")

        # Fill template
        reasoning = build_reasoning_text(
            candidate, replay_changed, replay_total,
            n_threshold=args.n, window_hours=args.window,
        )

        # Determine permissive_change (always 0 for BLOCK proposals)
        perm = 1 if is_permissive(proposed_yaml) else 0

        proposal = ProposedRule(
            proposal_id=str(uuid.uuid4()),
            created_at=time.time(),
            detection_rule="exact_match_frequency_v1",
            matched_binary=candidate.binary,
            matched_destination=candidate.destination,
            occurrence_count=candidate.occurrence_count,
            window_start=candidate.window_start,
            window_end=candidate.window_end,
            proposed_yaml_rule=proposed_yaml,
            status="pending",
            reasoning_text=reasoning,
            replay_total=replay_total,
            replay_changed=replay_changed,
            permissive_change=perm,
        )
        logger.write_proposed_rule(proposal)
        proposals_written += 1

    logger.close()

    print()
    print(f"Step 3/3: Wrote {proposals_written} proposal(s) to proposed_rules table.")
    print()
    print("=" * 60)
    print(f"Done. {proposals_written} pending proposal(s) ready for review.")
    print()
    print("To review and approve/reject proposals, run:")
    print(f"  python -m daemon.advisor.approval_cli --db {args.db} list")
    print(f"  python -m daemon.advisor.approval_cli --db {args.db} show <proposal_id>")
    print(f"  python -m daemon.advisor.approval_cli --db {args.db} approve <proposal_id>")
    print(f"  python -m daemon.advisor.approval_cli --db {args.db} reject <proposal_id>")
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
