#!/usr/bin/env python3
"""
demo/seed_phase3_data.py — Synthetic FLAG-event seeder for Phase 3 demos and tests.

Inserts realistic FLAG-verdict events directly into the events table via the
Logger's connection, using the same column layout the daemon writes in production.
Does NOT use raw fixtures that skip schema validation — every row goes through
a Logger-initialised SQLite connection so all schema guards and indexes apply.

CONTRACT: This script is WRITE-ONLY to the events table.
  It never touches proposed_rules, pending_actions, or policy.yaml.
  After seeding, the caller (run_phase3_demo.py or a test) reads back and scans.

WHY seed via direct SQL rather than Logger.record():
  Logger.record() requires a full LedgerEvent (ParsedAction + Verdict +
  ExecutionResult dataclasses). Building those objects for 50+ synthetic rows
  adds noise without testing anything about Phase 3 itself. The purpose of
  this script is to reproduce exactly the kind of rows the live daemon writes,
  so we use the same INSERT column set the daemon uses — validated by the
  schema CHECK constraints and indexes — but without the overhead of the full
  dataclass pipeline. The pattern matches what test_phase3_advisor.py's helpers
  already do.

WHY explicit negative controls:
  A scanner that fires on everything is no scanner at all. Two classes of
  negative control are seeded:
    1. "Window-expired" events: same (binary, destination) pairs but timestamped
       7 hours ago, outside the 6h rolling window. Total count would cross the
       threshold if the window were ignored.
    2. "Volume-shy" events: N-1 (9) events for a distinct pair, never reaching
       the threshold regardless of window.
  The demo asserts these do NOT appear in scan() output.

Usage:
  python demo/seed_phase3_data.py [--db warden_demo.db] [--clear]

  --clear:  wipes all rows from the events table before seeding.
            ONLY use this in demo/test contexts — never against a production DB.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# CONTRACT: import via package path — requires repo root on PYTHONPATH
# (satisfied by running from the repo root, e.g. `python demo/seed_phase3_data.py`)
from daemon.ledger.logger import Logger


# ── Constants ─────────────────────────────────────────────────────────────────

N_THRESHOLD  = 10     # must match detection_scanner default
WINDOW_HOURS = 6.0    # must match detection_scanner default


# ── Seed scenario definitions ──────────────────────────────────────────────────

# Each scenario is a dict describing one "batch" of synthetic events.
# Keys:
#   label        — human-readable name (printed in demo output)
#   event_type   — "shell_command" | "network"
#   binary       — binary field in parsed_action JSON
#   destination  — hostname_or_sni or dst_ip (see is_hostname below)
#   is_hostname  — True → use hostname_or_sni field; False → use dst_ip
#   count        — number of FLAG events to insert
#   age_hours    — how many hours ago these events occurred (0 = now)
#   expect_fire  — True if this batch alone should produce a detection candidate
#   note         — free text explaining why the batch is/isn't expected to fire

SEED_SCENARIOS: list[dict] = [
    # ── POSITIVE controls (MUST cross threshold) ──────────────────────────────

    {
        # Shell-origin, IP axis: 12 FLAG events for (curl, 10.0.0.1)
        # WHY 12 and not exactly 10: gives a clear margin above N to confirm
        # the scanner isn't doing off-by-one rounding.
        "label":       "shell-ip: curl → 10.0.0.1",
        "event_type":  "shell_command",
        "binary":      "curl",
        "destination": "10.0.0.1",
        "is_hostname": False,
        "count":       12,
        "age_hours":   1.0,
        "expect_fire": True,
        "note":        "Shell-origin IP axis: 12 FLAGs, well above N=10.",
    },
    {
        # Shell-origin, hostname axis: 11 FLAG events for (wget, exfil.evil.io)
        "label":       "shell-hostname: wget → exfil.evil.io",
        "event_type":  "shell_command",
        "binary":      "wget",
        "destination": "exfil.evil.io",
        "is_hostname": True,
        "count":       11,
        "age_hours":   2.0,
        "expect_fire": True,
        "note":        "Shell-origin hostname axis: 11 FLAGs, above N=10.",
    },
    {
        # Network-origin, IP axis: 15 FLAG events for 192.0.2.50 (no binary grouping)
        # Binary field is "<network>" (the daemon's sentinel for network events).
        "label":       "network-ip: <network> → 192.0.2.50",
        "event_type":  "network",
        "binary":      "<network>",
        "destination": "192.0.2.50",
        "is_hostname": False,
        "count":       15,
        "age_hours":   0.5,
        "expect_fire": True,
        "note":        "Network-origin IP axis: 15 FLAGs. Asymmetric grouping: binary ignored.",
    },
    {
        # Network-origin, hostname axis: 10 FLAG events for c2.attacker.net
        # Exactly at threshold — tests that N=10 is inclusive (>=), not exclusive (>).
        "label":       "network-hostname: <network> → c2.attacker.net",
        "event_type":  "network",
        "binary":      "<network>",
        "destination": "c2.attacker.net",
        "is_hostname": True,
        "count":       10,
        "age_hours":   1.0,
        "expect_fire": True,
        "note":        "Network-origin hostname axis: exactly N=10 FLAGs (boundary check).",
    },

    # ── NEGATIVE controls (must NOT produce a detection candidate) ─────────────

    {
        # Volume-shy: only 9 events — N-1. Should never fire regardless of window.
        "label":       "negative-volume: python3 → 203.0.113.1 (9 events)",
        "event_type":  "network",
        "binary":      "<network>",
        "destination": "203.0.113.1",
        "is_hostname": False,
        "count":       9,
        "age_hours":   0.5,
        "expect_fire": False,
        "note":        "Only 9 FLAGs — N-1. Must not produce a candidate.",
    },
    {
        # Window-expired: 12 events but all 7 hours ago (outside 6h window).
        # WHY: proves the scanner respects the rolling window cutoff.
        "label":       "negative-window: nc → 198.51.100.1 (12 events, 7h ago)",
        "event_type":  "network",
        "binary":      "<network>",
        "destination": "198.51.100.1",
        "is_hostname": False,
        "count":       12,
        "age_hours":   7.0,
        "expect_fire": False,
        "note":        "12 FLAGs but all 7h ago — outside 6h window. Must not fire.",
    },
    {
        # Hostname negative: 8 events for a hostname — stays below threshold.
        "label":       "negative-hostname-volume: python3 → benign-low.example.com (8 events)",
        "event_type":  "shell_command",
        "binary":      "python3",
        "destination": "benign-low.example.com",
        "is_hostname": True,
        "count":       8,
        "age_hours":   1.0,
        "expect_fire": False,
        "note":        "Only 8 hostname FLAGs for python3 — below N=10. Must not fire.",
    },
]


# ── Low-level insert helpers ───────────────────────────────────────────────────

def _ts(age_hours: float) -> str:
    """Return an ISO-8601 UTC timestamp for 'age_hours' hours ago."""
    t = time.time() - (age_hours * 3600.0)
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _make_network_blob(binary: str, destination: str, is_hostname: bool) -> str:
    """Build the parsed_action JSON blob for a network event row."""
    if is_hostname:
        # hostname_or_sni set; dst_ip set to a plausible value for the scenario
        return json.dumps({
            "binary":          binary,
            "raw_input":       f"TCP {destination}:443",
            "dst_ip":          "1.2.3.4",   # WHY: network detection on hostname axis
                                              # uses hostname_or_sni, not dst_ip.
                                              # Providing a plausible IP keeps rows realistic.
            "dst_port":        443,
            "protocol":        "TCP",
            "hostname_or_sni": destination,
            "direction":       "outbound",
        })
    else:
        return json.dumps({
            "binary":          binary,
            "raw_input":       f"TCP {destination}:80",
            "dst_ip":          destination,
            "dst_port":        80,
            "protocol":        "TCP",
            "hostname_or_sni": None,
            "direction":       "outbound",
        })


def _make_shell_blob(binary: str, destination: str, is_hostname: bool) -> str:
    """Build the parsed_action JSON blob for a shell_command event row.

    Shell FLAG events carry destination information in the parsed_action JSON
    so the detection scanner can group by (binary, dst_ip) or
    (binary, hostname_or_sni) on the shell axis. In production these come from
    ParsedAction objects that carry network metadata extracted by ShellParser;
    here we inject the same fields directly.
    """
    blob: dict = {
        "binary":      binary,
        "args":        [],
        "flags":       [],
        "target_paths": [],
        "raw_input":   binary,
        "sub_commands": [],
    }
    if is_hostname:
        blob["hostname_or_sni"] = destination
    else:
        blob["dst_ip"] = destination
    return json.dumps(blob)


def _insert_batch(
    logger: Logger,
    event_type: str,
    binary: str,
    destination: str,
    is_hostname: bool,
    count: int,
    age_hours: float,
) -> None:
    """Insert `count` FLAG rows for one scenario into the events table."""
    if event_type == "network":
        parsed_action = _make_network_blob(binary, destination, is_hostname)
        sql = """
            INSERT INTO events
                (timestamp, session_id, raw_input, event_type, verdict,
                 risk, execution, parsed_action, action_id)
            VALUES (?, ?, ?, 'network', 'FLAG', 'medium', 'none', ?, NULL)
        """
    else:
        parsed_action = _make_shell_blob(binary, destination, is_hostname)
        sql = """
            INSERT INTO events
                (timestamp, raw_input, parsed_action, event_type, verdict,
                 reason, execution, output, action_id)
            VALUES (?, ?, ?, 'shell_command', 'FLAG',
                    'seed: network exfiltration binary', 'none', '{}', NULL)
        """

    with logger._lock:
        for _ in range(count):
            # WHY slightly varied timestamp per row: identical timestamps would
            # make window_start == window_end in the scanner output, which looks
            # odd in the summary table. Small jitter (up to 5 min) within the
            # intended age keeps events realistic without affecting detection.
            import random
            jitter = random.uniform(0, 300)  # up to 5 minutes of jitter
            ts = _ts(age_hours - (jitter / 3600.0))

            if event_type == "network":
                logger._conn.execute(sql, (ts, "seed-session", f"seed:{binary}→{destination}", parsed_action))
            else:
                logger._conn.execute(sql, (ts, f"seed:{binary}→{destination}", parsed_action))
        logger._conn.commit()


# ── Public API (used by run_phase3_demo.py and tests) ─────────────────────────

def seed(db_path: Path, clear_first: bool = False) -> dict:
    """Insert all SEED_SCENARIOS into the DB at db_path.

    CONTRACT: Always idempotent when clear_first=False — rows are appended,
      not replaced. Pass clear_first=True only in demo/test contexts where a
      clean slate is needed.

    Returns a summary dict:
      {
        "db_path":    str,
        "rows_added": int,
        "scenarios":  list[dict],  # each scenario dict + "inserted" count
      }
    """
    logger = Logger(db_path)

    if clear_first:
        # WHY guard: clearing is irreversible. Print a visible warning so it
        # is never silently done in a context where real ledger data exists.
        print(f"[seed] WARNING: clearing all events rows in {db_path}")
        with logger._lock:
            logger._conn.execute("DELETE FROM events")
            logger._conn.commit()

    results = []
    total_inserted = 0

    for scenario in SEED_SCENARIOS:
        _insert_batch(
            logger        = logger,
            event_type    = scenario["event_type"],
            binary        = scenario["binary"],
            destination   = scenario["destination"],
            is_hostname   = scenario["is_hostname"],
            count         = scenario["count"],
            age_hours     = scenario["age_hours"],
        )
        results.append({**scenario, "inserted": scenario["count"]})
        total_inserted += scenario["count"]

    logger.close()

    return {
        "db_path":    str(db_path),
        "rows_added": total_inserted,
        "scenarios":  results,
    }


# ── CLI entry point ─────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Seed the Warden ledger with synthetic Phase 3 FLAG events.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--db", default="warden_demo.db", help="Path to warden SQLite DB")
    parser.add_argument(
        "--clear", action="store_true",
        help="Wipe the events table before seeding (demo/test only — irreversible)",
    )
    args = parser.parse_args()

    db_path = Path(args.db)
    print(f"[seed] Seeding {len(SEED_SCENARIOS)} scenarios into {db_path}")
    if args.clear:
        print("[seed] --clear flag set: events table will be wiped first")

    result = seed(db_path, clear_first=args.clear)

    print(f"[seed] Done. {result['rows_added']} rows inserted.")
    print()
    print(f"  {'Scenario':<50} {'Count':>5}  {'Expect fire':>11}  Notes")
    print(f"  {'-'*50} {'-'*5}  {'-'*11}  {'-'*30}")
    for s in result["scenarios"]:
        fire_str = "YES" if s["expect_fire"] else "no"
        print(f"  {s['label']:<50} {s['count']:>5}  {fire_str:>11}  {s['note']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
