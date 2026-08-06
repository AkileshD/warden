#!/usr/bin/env python3
"""
demo/run_phase3_demo.py — Phase 3 Smart Policy Loop: end-to-end integration demo.

Demonstrates the full detect → explain → replay chain in one run:

  Step 0: Confirm the ledger DB and policy.yaml exist
  Step 1: Seed synthetic FLAG events via seed_phase3_data.py
  Step 2: Run detection_scanner.scan() — print what fired, confirm proposed_rules rows
  Step 3: Run template_engine.build_reasoning_text() on each proposal — verify format
  Step 4: Run dry_run_replay.replay() on each proposal — print A-of-B impact
  Step 5: Print a final summary table (proposal_id, binary, destination,
          detection_axis, occurrence_count, replay impact)
  Step 6: Verify the negative controls did NOT produce any candidates

This script is the Phase 3 equivalent of demo/run_demo.py (Phase 1) and
demo/run_phase2_demo.py (Phase 2). It proves the pipeline works end-to-end
against a real SQLite DB using the exact same code paths that will run in
production, with no mocks.

WHY this demo seeds its own data (rather than relying on a pre-existing DB):
  The Phase 3 core is built and tested, but the Phase 3 integration end-to-end
  demo requires enough FLAG events to cross N=10/T=6h. Real agent sessions don't
  produce that volume reliably in a one-shot demo. Synthetic seeding is the right
  approach here — flagged in WARDEN_BUILD_CONTEXT.md and scoped explicitly.
  See also: WARDEN_SPEC.md §9 and WARDEN_BUILD_CONTEXT.md §4.

WHY a fresh --demo-db (not warden_demo.db by default):
  This demo seeds and clears events. Clearing warden_demo.db would destroy
  real session history. The demo uses a dedicated file by default, keeping
  the production ledger untouched.

Usage:
  python demo/run_phase3_demo.py
  python demo/run_phase3_demo.py --demo-db my_phase3.db --policy daemon/rules/policy.yaml
"""

from __future__ import annotations

import sys
from pathlib import Path

# WHY sys.path bootstrap: demo scripts are run directly (`python3 demo/run_phase3_demo.py`)
# from the repo root, not as installed packages. Python does not automatically add
# the repo root to sys.path in that case — it adds the script's own directory (demo/).
# Adding the repo root here lets `from daemon.xxx import ...` resolve correctly,
# matching the convention used by all other demo scripts that defer their imports
# inside main() after the same path surgery.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import argparse
import time
import uuid
from datetime import datetime, timezone



def _hr(char: str = "─", width: int = 70) -> str:
    return char * width


def _fmt_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _section(title: str) -> None:
    print()
    print(_hr("═"))
    print(f"  {title}")
    print(_hr("═"))


def _ok(msg: str) -> None:
    print(f"  ✅  {msg}")


def _fail(msg: str) -> None:
    print(f"  ❌  {msg}", file=sys.stderr)


def _info(msg: str) -> None:
    print(f"  ·   {msg}")


# ── Assertion helper (stops demo on hard failures) ─────────────────────────────

_failures: list[str] = []


def _assert(condition: bool, msg_pass: str, msg_fail: str) -> bool:
    if condition:
        _ok(msg_pass)
        return True
    else:
        _fail(msg_fail)
        _failures.append(msg_fail)
        return False


# ── Main demo ─────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Warden Phase 3 — end-to-end integration demo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--demo-db", default="phase3_demo.db",
        help="Path for the demo SQLite DB (will be seeded fresh; default: phase3_demo.db)",
    )
    parser.add_argument(
        "--policy", default="daemon/rules/policy.yaml",
        help="Path to policy.yaml (read-only; default: daemon/rules/policy.yaml)",
    )
    parser.add_argument(
        "--n", type=int, default=10,
        help="FLAG count threshold (default: 10, must match scanner default)",
    )
    parser.add_argument(
        "--window", type=float, default=6.0,
        help="Rolling window in hours (default: 6.0, must match scanner default)",
    )
    args = parser.parse_args()

    db_path     = Path(args.demo_db)
    policy_path = Path(args.policy)

    print(_hr("═"))
    print("  Warden Phase 3 — Smart Policy Loop: End-to-End Integration Demo")
    print(_hr("═"))
    print(f"  Demo DB:    {db_path.resolve()}")
    print(f"  Policy:     {policy_path.resolve()}")
    print(f"  Threshold:  N={args.n} FLAGs within T={args.window:.0f}h rolling window")

    # ── Step 0: Prerequisites ──────────────────────────────────────────────────
    _section("Step 0 — Prerequisites")

    if not policy_path.exists():
        _fail(f"policy.yaml not found at {policy_path}")
        return 1
    _ok(f"policy.yaml found at {policy_path}")

    # Import all Phase 3 components now so import errors are surfaced early
    try:
        from daemon.ledger.logger import Logger, ProposedRule
        from daemon.advisor.detection_scanner import scan, DetectionCandidate
        from daemon.advisor.dry_run_replay import replay
        from daemon.advisor.template_engine import (
            build_proposed_rule,
            build_reasoning_text,
            is_permissive,
            _is_hostname,
        )
        # WHY importlib (not `from demo.seed_phase3_data import ...`):
        # demo/ is not a Python package (no __init__.py); it is a scripts
        # directory. Package-style import would fail. importlib.util loads
        # it directly from its filesystem path — same pattern as the test
        # suite's conftest discovery and compatible with running from any cwd
        # as long as the repo root is on sys.path (satisfied by `python demo/...`).
        import importlib.util as _ilu
        _seed_path = Path(__file__).parent / "seed_phase3_data.py"
        _spec = _ilu.spec_from_file_location("seed_phase3_data", _seed_path)
        _seed_mod = _ilu.module_from_spec(_spec)
        _spec.loader.exec_module(_seed_mod)
        seed          = _seed_mod.seed
        SEED_SCENARIOS = _seed_mod.SEED_SCENARIOS
        N_THRESHOLD   = _seed_mod.N_THRESHOLD
        WINDOW_HOURS  = _seed_mod.WINDOW_HOURS
    except ImportError as e:
        _fail(f"Import failed: {e}")
        _fail("Run from the repo root: python demo/run_phase3_demo.py")
        return 1
    _ok("All Phase 3 modules imported successfully")

    # Confirm threshold params match seed script constants
    _assert(
        args.n == N_THRESHOLD and args.window == WINDOW_HOURS,
        f"Threshold params match seed script (N={N_THRESHOLD}, T={WINDOW_HOURS}h)",
        f"Threshold mismatch: demo uses N={args.n}/T={args.window}h "
        f"but seed script uses N={N_THRESHOLD}/T={WINDOW_HOURS}h — "
        "negative/positive controls will be unreliable",
    )

    # ── Step 1: Seed ───────────────────────────────────────────────────────────
    _section("Step 1 — Seeding Synthetic FLAG Events")

    expected_positive = [s for s in SEED_SCENARIOS if s["expect_fire"]]
    expected_negative = [s for s in SEED_SCENARIOS if not s["expect_fire"]]
    _info(f"Scenarios: {len(expected_positive)} positive controls, "
          f"{len(expected_negative)} negative controls")
    _info(f"Clearing demo DB before seed (demo only — never do this to warden_demo.db)")

    seed_result = seed(db_path, clear_first=True)

    # WHY also clear proposed_rules: seed() clears events, but proposed_rules
    # from a prior demo run persist. The assertion `len(pending) == len(candidates)`
    # at Step 3+4 would fail on the second run if old rows remain. This is a
    # demo-only context — clearing is safe and expected.
    from daemon.ledger.logger import Logger as _Logger
    _setup_logger = _Logger(db_path)
    with _setup_logger._lock:
        _setup_logger._conn.execute("DELETE FROM proposed_rules")
        _setup_logger._conn.commit()
    _setup_logger.close()
    _info("Cleared proposed_rules table (demo reset)")

    _assert(
        seed_result["rows_added"] > 0,
        f"{seed_result['rows_added']} event rows inserted into {db_path.name}",
        "Seed produced zero rows — something is wrong",
    )
    print()
    print(f"  {'Scenario':<52} {'N':>4}  {'Expect':>6}  Notes")
    print(f"  {'-'*52} {'-'*4}  {'-'*6}  {'-'*35}")
    for s in seed_result["scenarios"]:
        fire = "FIRE" if s["expect_fire"] else "no"
        print(f"  {s['label']:<52} {s['count']:>4}  {fire:>6}  {s['note']}")

    # ── Step 2: Detection ─────────────────────────────────────────────────────
    _section("Step 2 — Detection Scan")

    logger = Logger(db_path)
    candidates = scan(logger, n_threshold=args.n, window_hours=args.window)

    _assert(
        len(candidates) >= len(expected_positive),
        f"Found {len(candidates)} candidate(s) — at least {len(expected_positive)} expected",
        f"Found only {len(candidates)} candidate(s), expected ≥ {len(expected_positive)}",
    )

    # Confirm each positive scenario produced a candidate
    detected_destinations = {c.destination for c in candidates}
    for s in expected_positive:
        _assert(
            s["destination"] in detected_destinations,
            f"Detected: {s['label']}",
            f"MISSED positive control: {s['label']}",
        )

    # Confirm each negative scenario did NOT produce a candidate
    for s in expected_negative:
        _assert(
            s["destination"] not in detected_destinations,
            f"Correctly silent: {s['label']} (no candidate produced)",
            f"FALSE POSITIVE: {s['label']} should NOT have fired",
        )

    print()
    print(f"  {'#':<3} {'Binary':<16} {'Destination':<28} {'Axis':<10} {'Count':>5}")
    print(f"  {'-'*3} {'-'*16} {'-'*28} {'-'*10} {'-'*5}")
    for i, c in enumerate(candidates, 1):
        print(f"  {i:<3} {c.binary:<16} {c.destination:<28} {c.detection_axis:<10} {c.occurrence_count:>5}")

    # ── Step 3 + 4: Template fill + Replay + Write proposals ──────────────────
    _section("Step 3+4 — Template Fill, Dry-Run Replay, Proposal Write")

    written_proposals: list[dict] = []

    for i, candidate in enumerate(candidates, 1):
        print()
        print(f"  [{i}/{len(candidates)}] {candidate.binary} → {candidate.destination} "
              f"(axis={candidate.detection_axis}, count={candidate.occurrence_count})")

        # Build YAML rule
        proposed_yaml = build_proposed_rule(candidate)

        # Step 3: Verify reasoning text format per §9 template
        replay_changed, replay_total = replay(candidate, proposed_yaml, policy_path, logger)
        reasoning = build_reasoning_text(
            candidate, replay_changed, replay_total,
            n_threshold=args.n, window_hours=args.window,
        )

        # CONTRACT: every number in reasoning_text must trace back to real data
        checks = [
            (str(candidate.occurrence_count) in reasoning, "occurrence_count in reasoning"),
            (str(replay_changed)             in reasoning, "replay_changed in reasoning"),
            (str(replay_total)               in reasoning, "replay_total in reasoning"),
            (f"N={args.n}"                   in reasoning, f"N={args.n} in reasoning"),
            (f"T={args.window:.0f}h"         in reasoning, f"T={args.window:.0f}h in reasoning"),
            (candidate.binary                in reasoning, "binary in reasoning"),
            (candidate.destination           in reasoning, "destination in reasoning"),
        ]
        all_ok = True
        for passed, label in checks:
            if not passed:
                _fail(f"  Template check FAILED: '{label}' missing from reasoning_text")
                _failures.append(f"Template check failed: {label}")
                all_ok = False
        if all_ok:
            _ok(f"  Step 3: reasoning_text passes all §9 template field checks")

        # Step 4: Replay output
        _info(f"  Step 4: Replay: {replay_changed} of {replay_total} events "
              f"would change verdict (FLAG → BLOCK)")

        # WHY conditional: network-origin events whose binary could not be
        # attributed via action_id correlation degrade to "unknown source" or
        # "multiple sources". read_events_for_pair queries by binary name, so
        # it returns 0 rows for "unknown source" — this is correct behavior
        # (the binary label is a display-only best-effort, not a ledger field).
        # Only assert replay_total > 0 for candidates with a real attributed binary.
        _UNATTRIBUTED = {"unknown source", "multiple sources"}
        if candidate.binary not in _UNATTRIBUTED:
            _assert(
                replay_total > 0,
                f"  Step 4: replay_total={replay_total} > 0 — ledger rows found for this pair",
                f"  Step 4: replay_total=0 — no events found for {candidate.binary} → {candidate.destination}",
            )
        else:
            _info(f"  Step 4: replay_total=0 expected — binary attribution is '{candidate.binary}' "
                  f"(unattributed network event, replay skipped by design)")

        # Indented reasoning text (matches approval_cli show output format)
        print()
        print("  Reasoning text:")
        for line in reasoning.splitlines():
            print(f"    {line}")
        print()
        print("  Proposed YAML rule:")
        print("  ---")
        for line in proposed_yaml.splitlines():
            print(f"  {line}")
        print("  ---")

        # Write proposed_rule row
        perm = 1 if is_permissive(proposed_yaml) else 0
        proposal_id = str(uuid.uuid4())
        proposal = ProposedRule(
            proposal_id       = proposal_id,
            created_at        = time.time(),
            detection_rule    = "exact_match_frequency_v1",
            matched_binary    = candidate.binary,
            matched_destination = candidate.destination,
            detection_axis    = candidate.detection_axis,
            occurrence_count  = candidate.occurrence_count,
            window_start      = candidate.window_start,
            window_end        = candidate.window_end,
            proposed_yaml_rule = proposed_yaml,
            status            = "pending",
            reasoning_text    = reasoning,
            replay_total      = replay_total,
            replay_changed    = replay_changed,
            permissive_change = perm,
        )
        logger.write_proposed_rule(proposal)
        written_proposals.append({
            "proposal_id":    proposal_id,
            "binary":         candidate.binary,
            "destination":    candidate.destination,
            "axis":           candidate.detection_axis,
            "count":          candidate.occurrence_count,
            "replay_changed": replay_changed,
            "replay_total":   replay_total,
            "permissive":     perm,
        })

    # Verify all proposals landed in proposed_rules with status='pending'
    pending = logger.list_pending_proposals()
    _assert(
        len(pending) == len(candidates),
        f"All {len(candidates)} proposals written to proposed_rules with status='pending'",
        f"Expected {len(candidates)} pending proposals, found {len(pending)}",
    )

    logger.close()

    # ── Step 5: Summary table ─────────────────────────────────────────────────
    _section("Step 5 — Final Summary")

    print()
    header = (
        f"  {'Proposal ID':>10}  {'Binary':<16}  {'Destination':<28}  "
        f"{'Axis':<10}  {'Count':>5}  {'Replay':>12}  {'Permissive':>10}"
    )
    print(header)
    print(f"  {'-'*10}  {'-'*16}  {'-'*28}  {'-'*10}  {'-'*5}  {'-'*12}  {'-'*10}")

    for p in written_proposals:
        short_id = p["proposal_id"][:8]
        replay_str = f"{p['replay_changed']}/{p['replay_total']}"
        perm_str = "YES ⚠" if p["permissive"] else "No"
        print(
            f"  {short_id:>10}  {p['binary']:<16}  {p['destination']:<28}  "
            f"{p['axis']:<10}  {p['count']:>5}  {replay_str:>12}  {perm_str:>10}"
        )

    print()
    print("  Chain verified: detect → explain → replay → proposed_rules write")
    print()

    # ── Step 6: Negative control summary ─────────────────────────────────────
    _section("Step 6 — Negative Control Verification")

    neg_destinations = {s["destination"] for s in expected_negative}
    detected_neg = [c for c in candidates if c.destination in neg_destinations]

    _assert(
        len(detected_neg) == 0,
        f"All {len(expected_negative)} negative controls correctly silent "
        f"(window-expired and volume-shy events did not fire)",
        f"{len(detected_neg)} negative control(s) incorrectly fired: "
        f"{[c.destination for c in detected_neg]}",
    )

    for s in expected_negative:
        _info(f"{s['label']}: {s['note']}")

    # ── Final result ──────────────────────────────────────────────────────────
    _section("Result")

    if _failures:
        print(f"  ❌  {len(_failures)} assertion(s) FAILED:")
        for f in _failures:
            print(f"      · {f}")
        print()
        return 1
    else:
        print(f"  ✅  All assertions passed.")
        print(f"  ✅  {len(written_proposals)} proposal(s) written and verified.")
        print(f"  ✅  {len(expected_negative)} negative control(s) correctly silent.")
        print()
        print("  To review and act on proposals, run:")
        print(f"    python -m daemon.advisor.approval_cli --db {db_path} list")
        print(f"    python -m daemon.advisor.approval_cli --db {db_path} show <proposal_id>")
        print(f"    python -m daemon.advisor.approval_cli --db {db_path} approve <proposal_id>")
        print()
        return 0


if __name__ == "__main__":
    sys.exit(main())
