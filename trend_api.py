"""
XentinelAI — Security Score Trend API
Returns historical score data for the trendline graph.
Reads from existing saved report JSONs in REPORTS_DIR.

Endpoint: GET /scans/trend
Drop-in: no existing files changed except main.py (one endpoint added).
"""

import os
import json
from pathlib import Path
from typing import List, Dict, Any


def get_trend_data(reports_dir: str, limit: int = 50) -> Dict[str, Any]:
    """
    Read all saved scan reports and extract trend data.
    Returns structured data for the frontend chart.
    """
    reports = sorted(
        Path(reports_dir).glob("*.json"),
        key=lambda p: p.stat().st_mtime,
        reverse=False,   # oldest first for chart
    )

    points = []
    for r in reports[-limit:]:
        try:
            with open(r, encoding="utf-8") as f:
                data = json.load(f)

            stats      = data.get("stats", {})
            scanned_at = data.get("scanned_at", "")[:10]
            repo       = data.get("repo", "unknown")
            scan_id    = data.get("scan_id", "")
            total      = stats.get("total", 0)
            critical   = stats.get("critical", 0)
            high       = stats.get("high", 0)
            medium     = stats.get("medium", 0)
            chains     = stats.get("attack_chains", 0)

            # Compute security score (0–100, higher = better)
            # risk_trend.py stores score inverted (100 = most vulnerable)
            # so always recompute from stats for correct graph direction.
            score = _compute_score(total, critical, high, medium)

            points.append({
                "scan_id":    scan_id,
                "repo":       repo,
                "date":       scanned_at,
                "score":      score,
                "total":      total,
                "critical":   critical,
                "high":       high,
                "medium":     medium,
                "chains":     chains,
                "grade":      _grade(score),
            })
        except Exception:
            continue

    if not points:
        return {"points": [], "repos": [], "summary": "No scan history found."}

    # Group by repo for multi-repo support
    repos = list(dict.fromkeys(p["repo"] for p in points))

    # Compute improvement delta
    latest = points[-1] if points else {}
    oldest = points[0]  if points else {}
    delta  = latest.get("score", 0) - oldest.get("score", 0) if len(points) > 1 else 0

    return {
        "points":   points,
        "repos":    repos,
        "latest":   latest,
        "delta":    delta,
        "improved": delta > 0,
        "summary": (
            f"{len(points)} scan{'s' if len(points) != 1 else ''} recorded. "
            f"Latest score: {latest.get('score', 0)}/100 ({latest.get('grade', '?')}). "
            + (f"{'▲ Improved' if delta > 0 else '▼ Regressed'} {abs(delta)} pts since first scan."
               if len(points) > 1 else "First scan — baseline established.")
        ),
    }


def _compute_score(total: int, critical: int, high: int, medium: int) -> int:
    if total == 0:
        return 100
    penalty = (critical * 10) + (high * 4) + (medium * 1)
    score   = max(0, 100 - penalty)
    return score


def _grade(score: int) -> str:
    if score >= 90: return "A"
    if score >= 75: return "B"
    if score >= 60: return "C"
    if score >= 40: return "D"
    return "F"
