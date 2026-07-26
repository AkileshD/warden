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
      detection_axis   — 'ip' or 'hostname', indicating which query generated this candidate
      occurrence_count — number of FLAG verdicts in the window
      window_start     — Unix timestamp: earliest matching event in window
      window_end       — Unix timestamp: latest matching event in window
    """
    binary: str
    destination: str
    detection_axis: str
    occurrence_count: int
    window_start: float
    window_end: float

# LIMITATION: Partial Visibility
# This resolver only sees binaries from network events that successfully 
# preserved an action_id correlation back to their originating shell_command. 
# Therefore, the displayed binary(s) may not represent every source that 
# actually contributed to the destination's threshold count.
def _resolve_network_binary(logger: "Logger", destination: str, detection_axis: str, cutoff: float) -> str:
    dst_field = "dst_ip" if detection_axis == "ip" else "hostname_or_sni"
    query = f"""
        SELECT DISTINCT json_extract(e2.parsed_action, '$.binary')
        FROM events e1
        JOIN events e2 ON e1.action_id = e2.action_id
        WHERE e1.event_type = 'network'
          AND json_extract(e1.parsed_action, '$.{dst_field}') = ?
          AND e1.verdict = 'FLAG'
          AND CAST(strftime('%s', e1.timestamp) AS REAL) >= ?
          AND e2.event_type = 'shell_command'
          AND e1.action_id IS NOT NULL
    """
    cursor = logger._conn.execute(query, (destination, cutoff))
    binaries = [row[0] for row in cursor.fetchall() if row[0]]
    if len(binaries) == 1:
        return binaries[0]
    elif len(binaries) > 1:
        return "multiple sources"
    else:
        return "unknown source"


def scan(
    logger: "Logger",
    n_threshold: int = 10,
    window_hours: float = 6.0,
) -> list[DetectionCandidate]:
    """Scan the events table for patterns crossing the FLAG-count threshold.

    Detection rule (from WARDEN_SPEC.md §9):
      - Shell-origin events grouped by (binary, destination)
      - Network-origin events grouped by (destination) alone

    Args:
      logger:       Logger instance (provides the SQLite connection under lock).
      n_threshold:  Minimum FLAG count to generate a candidate. Default: 10.
      window_hours: Rolling window length in hours. Default: 6.0.

    Returns:
      List of DetectionCandidate, ordered by occurrence_count descending.

    CONTRACT: Pure read — never writes to events; may write nothing on error.
    Network-origin candidate binaries are best-effort and derived from
    correlated shell events only.
    """
    cutoff = time.time() - (window_hours * 3600.0)

    sql_shell_ip = """
    SELECT
        json_extract(parsed_action, '$.binary')             AS binary,
        json_extract(parsed_action, '$.dst_ip')             AS destination,
        COUNT(*)                                            AS occurrence_count,
        MIN(CAST(strftime('%s', timestamp) AS REAL))        AS window_start,
        MAX(CAST(strftime('%s', timestamp) AS REAL))        AS window_end
    FROM events
    WHERE
        verdict = 'FLAG'
        AND event_type = 'shell_command'
        AND CAST(strftime('%s', timestamp) AS REAL) >= :cutoff
        AND json_extract(parsed_action, '$.dst_ip') IS NOT NULL
    GROUP BY binary, destination
    HAVING COUNT(*) >= :n_threshold
    """

    sql_shell_hostname = """
    SELECT
        json_extract(parsed_action, '$.binary')             AS binary,
        json_extract(parsed_action, '$.hostname_or_sni')    AS destination,
        COUNT(*)                                            AS occurrence_count,
        MIN(CAST(strftime('%s', timestamp) AS REAL))        AS window_start,
        MAX(CAST(strftime('%s', timestamp) AS REAL))        AS window_end
    FROM events
    WHERE
        verdict = 'FLAG'
        AND event_type = 'shell_command'
        AND CAST(strftime('%s', timestamp) AS REAL) >= :cutoff
        AND json_extract(parsed_action, '$.hostname_or_sni') IS NOT NULL
    GROUP BY binary, destination
    HAVING COUNT(*) >= :n_threshold
    """

    sql_network_ip = """
    SELECT
        json_extract(parsed_action, '$.dst_ip')             AS destination,
        COUNT(*)                                            AS occurrence_count,
        MIN(CAST(strftime('%s', timestamp) AS REAL))        AS window_start,
        MAX(CAST(strftime('%s', timestamp) AS REAL))        AS window_end
    FROM events
    WHERE
        verdict = 'FLAG'
        AND event_type = 'network'
        AND CAST(strftime('%s', timestamp) AS REAL) >= :cutoff
        AND json_extract(parsed_action, '$.dst_ip') IS NOT NULL
    GROUP BY destination
    HAVING COUNT(*) >= :n_threshold
    """

    sql_network_hostname = """
    SELECT
        json_extract(parsed_action, '$.hostname_or_sni')    AS destination,
        COUNT(*)                                            AS occurrence_count,
        MIN(CAST(strftime('%s', timestamp) AS REAL))        AS window_start,
        MAX(CAST(strftime('%s', timestamp) AS REAL))        AS window_end
    FROM events
    WHERE
        verdict = 'FLAG'
        AND event_type = 'network'
        AND CAST(strftime('%s', timestamp) AS REAL) >= :cutoff
        AND json_extract(parsed_action, '$.hostname_or_sni') IS NOT NULL
    GROUP BY destination
    HAVING COUNT(*) >= :n_threshold
    """

    candidates = []
    try:
        with logger._lock:
            # 1. Shell IP axis
            cursor_shell_ip = logger._conn.execute(sql_shell_ip, {"cutoff": cutoff, "n_threshold": n_threshold})
            for row in cursor_shell_ip.fetchall():
                binary, destination, count, win_start, win_end = row
                if binary and destination:
                    candidates.append(DetectionCandidate(
                        binary=binary,
                        destination=destination,
                        detection_axis="ip",
                        occurrence_count=count,
                        window_start=float(win_start) if win_start else cutoff,
                        window_end=float(win_end) if win_end else time.time(),
                    ))

            # 2. Shell Hostname axis
            cursor_shell_hostname = logger._conn.execute(sql_shell_hostname, {"cutoff": cutoff, "n_threshold": n_threshold})
            for row in cursor_shell_hostname.fetchall():
                binary, destination, count, win_start, win_end = row
                if binary and destination:
                    candidates.append(DetectionCandidate(
                        binary=binary,
                        destination=destination,
                        detection_axis="hostname",
                        occurrence_count=count,
                        window_start=float(win_start) if win_start else cutoff,
                        window_end=float(win_end) if win_end else time.time(),
                    ))

            # 3. Network IP axis
            cursor_net_ip = logger._conn.execute(sql_network_ip, {"cutoff": cutoff, "n_threshold": n_threshold})
            for row in cursor_net_ip.fetchall():
                destination, count, win_start, win_end = row
                if destination:
                    try:
                        binary = _resolve_network_binary(logger, destination, "ip", cutoff)
                    except Exception:
                        binary = "unknown source"
                    candidates.append(DetectionCandidate(
                        binary=binary,
                        destination=destination,
                        detection_axis="ip",
                        occurrence_count=count,
                        window_start=float(win_start) if win_start else cutoff,
                        window_end=float(win_end) if win_end else time.time(),
                    ))

            # 4. Network Hostname axis
            cursor_net_hostname = logger._conn.execute(sql_network_hostname, {"cutoff": cutoff, "n_threshold": n_threshold})
            for row in cursor_net_hostname.fetchall():
                destination, count, win_start, win_end = row
                if destination:
                    try:
                        binary = _resolve_network_binary(logger, destination, "hostname", cutoff)
                    except Exception:
                        binary = "unknown source"
                    candidates.append(DetectionCandidate(
                        binary=binary,
                        destination=destination,
                        detection_axis="hostname",
                        occurrence_count=count,
                        window_start=float(win_start) if win_start else cutoff,
                        window_end=float(win_end) if win_end else time.time(),
                    ))
    except Exception as e:
        import sys
        print(f"[detection_scanner] ERROR running scan query: {e}", file=sys.stderr)
        return []

    # Sort descending by occurrence_count
    candidates.sort(key=lambda c: c.occurrence_count, reverse=True)

    return candidates
