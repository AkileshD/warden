"""
daemon/advisor/detection_scanner.py — Phase 3 pattern detection.

Reads the events table, applies the N=10/T=6h binary+destination FLAG-count
rule from WARDEN_SPEC.md §9, and returns DetectionCandidate objects.

CONTRACT: scan() is PURE READ — no writes, no side effects. The caller
  (demo/run_phase3_advisor.py) handles all writes after reviewing results.
  This keeps the scanner stateless and trivially testable without mocks.

WHY a one-off script invocation (not a background daemon thread):
  The detection algorithm needs validation against real ledger data before
  being committed to a continuous loop. A manually-invoked scanner lets us
  tune N and T and verify proposal quality first. A scheduled runner is a
  Phase 3+ backlog item once the rule is proven correct.
"""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from daemon.ledger.logger import Logger


@dataclass
class DetectionCandidate:
    """
    One detected pattern that crossed the N/T threshold.

    Fields:
      binary           — the binary name (e.g. 'curl', 'python3')
      destination      — hostname_or_sni if available, else dst_ip
      occurrence_count — number of FLAG verdicts in the window
      window_start     — Unix timestamp: earliest matching event in window
      window_end       — Unix timestamp: latest matching event in window
    """
    binary: str
    destination: str
    occurrence_count: int
    window_start: float
    window_end: float


def scan(
    logger: "Logger",
    n_threshold: int = 10,
    window_hours: float = 6.0,
) -> list[DetectionCandidate]:
    """Scan the events table for (binary, destination) pairs that crossed
    the FLAG-count threshold within the rolling time window.

    Detection rule (from WARDEN_SPEC.md §9):
      Same (binary, COALESCE(hostname_or_sni, dst_ip)) combination received
      a FLAG verdict >= n_threshold times within the last window_hours hours.

    Args:
      logger:       Logger instance (provides the SQLite connection under lock).
      n_threshold:  Minimum FLAG count to generate a candidate. Default: 10.
      window_hours: Rolling window length in hours. Default: 6.0.

    Returns:
      List of DetectionCandidate, ordered by occurrence_count descending.
      Empty list if no pair crossed the threshold or the events table is empty.

    CONTRACT: Pure read — never writes, never raises (returns empty list on error).
    """
    # WHY network events only: shell FLAG events are a different signal and are
    # already visible in the ledger for human review. The Phase 3 initial rule
    # specifically targets network destinations as the attack surface most likely
    # to benefit from auto-proposed BLOCK rules.
    cutoff = time.time() - (window_hours * 3600.0)

    sql = """
    SELECT
        json_extract(parsed_action, '$.binary')             AS binary,
        COALESCE(
            json_extract(parsed_action, '$.hostname_or_sni'),
            json_extract(parsed_action, '$.dst_ip')
        )                                                    AS destination,
        COUNT(*)                                             AS occurrence_count,
        MIN(CAST(timestamp AS REAL))                         AS window_start,
        MAX(CAST(timestamp AS REAL))                         AS window_end
    FROM events
    WHERE
        verdict = 'FLAG'
        AND event_type = 'network'
        AND CAST(timestamp AS REAL) >= :cutoff
        AND COALESCE(
            json_extract(parsed_action, '$.hostname_or_sni'),
            json_extract(parsed_action, '$.dst_ip')
        ) IS NOT NULL
    GROUP BY binary, destination
    HAVING COUNT(*) >= :n_threshold
    ORDER BY occurrence_count DESC
    """

    try:
        with logger._lock:
            cursor = logger._conn.execute(sql, {"cutoff": cutoff, "n_threshold": n_threshold})
            rows = cursor.fetchall()
    except Exception as e:
        import sys
        print(f"[detection_scanner] ERROR running scan query: {e}", file=sys.stderr)
        return []

    candidates = []
    for row in rows:
        binary, destination, count, win_start, win_end = row
        if binary and destination:
            candidates.append(DetectionCandidate(
                binary=binary,
                destination=destination,
                occurrence_count=count,
                window_start=float(win_start) if win_start else cutoff,
                window_end=float(win_end) if win_end else time.time(),
            ))

    return candidates
