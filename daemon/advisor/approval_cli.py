"""
daemon/advisor/approval_cli.py — Human approval interface for Phase 3 proposals.

Usage:
  python -m daemon.advisor.approval_cli list
  python -m daemon.advisor.approval_cli show <proposal_id>
  python -m daemon.advisor.approval_cli reject <proposal_id>
  python -m daemon.advisor.approval_cli approve <proposal_id> [--confirm-permissive]

CONTRACT: This script NEVER writes to policy.yaml. On approval, it marks the
  DB row as 'approved' and prints the proposed YAML with copy-paste instructions.
  The human remains the sole author of the enforced policy. This is a deliberate
  architectural safety choice — see WARDEN_SPEC.md §9.

WHY no auto-write to policy.yaml:
  Automatic policy mutation — even on an approved proposal — removes the moment
  of human contact with the exact text that will be enforced. The copy-paste
  step is the final safety gate. Revisit only after Phase 3 has been used in
  practice and there is clear evidence this step causes friction rather than
  value.

WHY asymmetric scrutiny (--confirm-permissive):
  Restrictive proposals (BLOCK) tighten policy — the worst outcome is an
  over-blocking false positive. Permissive proposals (ALLOW) expand the attack
  surface — the worst outcome is an under-blocking miss with real consequences.
  The approval path for permissive rules requires an explicit flag AND a typed
  confirmation phrase. This asymmetry is structural, not a norm.
"""

from __future__ import annotations

import argparse
import sys
import textwrap
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_DB = "warden_demo.db"


def _get_logger(db_path: str):
    from daemon.ledger.logger import Logger
    return Logger(Path(db_path))


def _fmt_timestamp(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _short_id(proposal_id: str) -> str:
    return proposal_id[:8]


# ------------------------------------------------------------------
# Command implementations (pure functions — testable without argparse)
# ------------------------------------------------------------------

def cmd_list(db_path: str) -> int:
    logger = _get_logger(db_path)
    proposals = logger.list_pending_proposals()
    logger.close()

    if not proposals:
        print("No pending proposals.")
        return 0

    print(f"{'ID':8}  {'Binary':12}  {'Destination':30}  {'Count':5}  {'Replay':12}  Status")
    print("-" * 88)
    for p in proposals:
        replay_str = f"{p['replay_changed']}/{p['replay_total']}"
        print(
            f"{_short_id(p['proposal_id']):8}  "
            f"{p['matched_binary']:12}  "
            f"{p['matched_destination'][:30]:30}  "
            f"{p['occurrence_count']:5}  "
            f"{replay_str:12}  "
            f"{p['status']}"
        )
        # Indent reasoning text beneath each row
        for line in p["reasoning_text"].splitlines():
            print(f"          {line}")
        print()
    return 0


def cmd_show(db_path: str, proposal_id: str) -> int:
    logger = _get_logger(db_path)
    p = _find_proposal(logger, proposal_id)
    logger.close()

    if p is None:
        print(f"Error: proposal '{proposal_id}' not found.", file=sys.stderr)
        return 1

    print(f"Proposal ID:   {p['proposal_id']}")
    print(f"Status:        {p['status']}")
    print(f"Created:       {_fmt_timestamp(p['created_at'])}")
    print(f"Binary:        {p['matched_binary']}")
    print(f"Destination:   {p['matched_destination']}")
    print(f"Count:         {p['occurrence_count']}")
    print(f"Window:        {_fmt_timestamp(p['window_start'])} → {_fmt_timestamp(p['window_end'])}")
    print(f"Replay:        {p['replay_changed']} of {p['replay_total']} events would change")
    print(f"Permissive:    {'YES ⚠' if p['permissive_change'] else 'No'}")
    print()
    print("Reasoning:")
    print(textwrap.indent(p["reasoning_text"], "  "))
    print()
    print("Proposed YAML rule:")
    print("---")
    print(p["proposed_yaml_rule"])
    print("---")
    return 0


def cmd_reject(db_path: str, proposal_id: str) -> int:
    logger = _get_logger(db_path)
    p = _find_proposal(logger, proposal_id)
    if p is None:
        logger.close()
        print(f"Error: proposal '{proposal_id}' not found.", file=sys.stderr)
        return 1
    if p["status"] != "pending":
        logger.close()
        print(f"Error: proposal is already '{p['status']}' (not pending).", file=sys.stderr)
        return 1

    logger.update_proposal_status(p["proposal_id"], "rejected")
    logger.close()
    print(f"Proposal {_short_id(p['proposal_id'])} marked REJECTED.")
    return 0


def cmd_approve(db_path: str, proposal_id: str, confirm_permissive: bool) -> int:
    """Approve a proposal with asymmetric scrutiny for permissive rules.

    For BLOCK proposals (permissive_change=0): single y/N prompt.
    For ALLOW proposals (permissive_change=1): requires --confirm-permissive flag
      AND a typed confirmation phrase before any DB write.

    CONTRACT: no DB write occurs unless ALL confirmation steps succeed.
    """
    logger = _get_logger(db_path)
    p = _find_proposal(logger, proposal_id)

    if p is None:
        logger.close()
        print(f"Error: proposal '{proposal_id}' not found.", file=sys.stderr)
        return 1
    if p["status"] != "pending":
        logger.close()
        print(f"Error: proposal is already '{p['status']}' (not pending).", file=sys.stderr)
        return 1

    is_permissive_change = bool(p["permissive_change"])

    # Asymmetric scrutiny gate
    if is_permissive_change:
        if not confirm_permissive:
            logger.close()
            print(
                "Error: this proposal EXPANDS permissions (action: allow).\n"
                "Approving it reduces Warden's blocking surface. This requires "
                "explicit confirmation.\n"
                "Re-run with the --confirm-permissive flag to proceed.",
                file=sys.stderr,
            )
            return 2  # distinct exit code for permissive-gate failure

        # Harder confirmation: must type the exact phrase
        print("\n⚠  WARNING: This rule EXPANDS PERMISSIONS (action: allow).")
        print("   Approving this rule allows traffic that was previously flagged.")
        print()
        phrase = input("Type exactly 'I understand the risk' to confirm: ").strip()
        if phrase != "I understand the risk":
            logger.close()
            print("Confirmation text did not match. Approval cancelled.", file=sys.stderr)
            return 1
    else:
        # Restrictive change: single y/N prompt
        print(f"Approve proposal {_short_id(p['proposal_id'])}?")
        print(f"  Binary: {p['matched_binary']}  Destination: {p['matched_destination']}")
        print(f"  Replay: {p['replay_changed']} of {p['replay_total']} events would change")
        answer = input("Confirm? [y/N]: ").strip().lower()
        if answer != "y":
            logger.close()
            print("Approval cancelled.")
            return 0

    # All gates passed — mark approved
    logger.update_proposal_status(p["proposal_id"], "approved")
    logger.close()

    print(f"\nProposal {_short_id(p['proposal_id'])} marked APPROVED.")
    print()
    print("To apply this rule, add the following to policy.yaml")
    print("(under network_rules, before the catch-all BLOCK):")
    print()
    print("---")
    print(p["proposed_yaml_rule"])
    print("---")
    print()
    print("No automatic changes have been made to policy.yaml.")
    print("This is a deliberate safety choice: the human remains")
    print("the sole author of the enforced policy.")
    return 0


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _find_proposal(logger, proposal_id: str):
    """Resolve a full or partial (prefix) proposal_id to a row dict."""
    # Try exact match first
    p = logger.get_proposal(proposal_id)
    if p:
        return p

    # Try prefix match (user typed first 8 chars from 'list' output)
    all_proposals = logger.list_all_proposals()
    matches = [row for row in all_proposals if row["proposal_id"].startswith(proposal_id)]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        print(
            f"Error: '{proposal_id}' is ambiguous — matches {len(matches)} proposals. "
            "Use a longer prefix.",
            file=sys.stderr,
        )
        return None
    return None


def check_approve_permissive_gate(proposal: dict, confirm_permissive: bool) -> tuple[bool, str]:
    """Pure function: check whether an approve call may proceed.

    Returns (allowed: bool, error_message: str).
    Used directly in tests without running interactive prompts.
    """
    if proposal["permissive_change"] and not confirm_permissive:
        return False, (
            "This proposal EXPANDS permissions (action: allow). "
            "Re-run with --confirm-permissive to proceed."
        )
    return True, ""


# ------------------------------------------------------------------
# CLI entry point
# ------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Warden Phase 3 — proposal approval CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--db", default=DEFAULT_DB, help="Path to warden SQLite DB")

    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("list", help="List all pending proposals")

    show_p = subparsers.add_parser("show", help="Show full detail for a proposal")
    show_p.add_argument("proposal_id")

    reject_p = subparsers.add_parser("reject", help="Reject a proposal")
    reject_p.add_argument("proposal_id")

    approve_p = subparsers.add_parser("approve", help="Approve a proposal")
    approve_p.add_argument("proposal_id")
    approve_p.add_argument(
        "--confirm-permissive",
        action="store_true",
        help="Required when approving a rule that expands permissions (action: allow)",
    )

    args = parser.parse_args()

    if args.command == "list":
        return cmd_list(args.db)
    elif args.command == "show":
        return cmd_show(args.db, args.proposal_id)
    elif args.command == "reject":
        return cmd_reject(args.db, args.proposal_id)
    elif args.command == "approve":
        return cmd_approve(args.db, args.proposal_id, args.confirm_permissive)

    return 0


if __name__ == "__main__":
    sys.exit(main())
