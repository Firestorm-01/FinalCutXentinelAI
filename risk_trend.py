"""
risk_trend.py — Risk Score Trend Calculator
Compares current scan against previous scan of the same repo.
Drop-in utility — no changes to existing files required.
Import: from risk_trend import compute_trend, attach_trend
"""
import json
import os
from pathlib import Path
from typing import Optional


def _score_from_stats(stats: dict) -> int:
    """
    Compute a 0-100 risk score from scan stats.
    Higher score = worse security posture.
    Weighted: critical=10pts, high=5pts, medium=2pts, low=1pt (capped at 100).
    """
    score = (
        stats.get("critical", 0) * 10 +
        stats.get("high",     0) * 5  +
        stats.get("medium",   0) * 2  +
        stats.get("low",      0) * 1
    )
    return min(score, 100)


def _letter_grade(score: int) -> str:
    if score == 0:   return "A+"
    if score <= 10:  return "A"
    if score <= 25:  return "B"
    if score <= 45:  return "C"
    if score <= 65:  return "D"
    return "F"


def compute_trend(
    current_scan_id: str,
    current_stats:   dict,
    repo_name:       str,
    reports_dir:     str,
) -> dict:
    """
    Find the most recent previous scan of the same repo and compute delta.
    Returns a trend dict safe to embed in the scan response or serve as API data.
    """
    current_score = _score_from_stats(current_stats)
    current_grade = _letter_grade(current_score)

    # Gather all reports for this repo (excluding current scan)
    previous_scans = []
    try:
        for report_path in sorted(
            Path(reports_dir).glob("*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        ):
            if report_path.stem == current_scan_id:
                continue
            try:
                with open(report_path, encoding="utf-8") as f:
                    data = json.load(f)
                if data.get("repo") == repo_name and data.get("stats"):
                    previous_scans.append(data)
            except Exception:
                continue
    except Exception:
        pass

    if not previous_scans:
        # First scan for this repo — no trend yet
        return {
            "current_score":  current_score,
            "current_grade":  current_grade,
            "previous_score": None,
            "delta":          None,
            "direction":      "first_scan",
            "message":        f"First scan of '{repo_name}' — baseline established.",
            "scan_count":     1,
        }

    prev = previous_scans[0]
    previous_score = _score_from_stats(prev["stats"])
    previous_grade = _letter_grade(previous_score)
    delta = current_score - previous_score  # positive = got worse, negative = improved
    scan_count = len(previous_scans) + 1

    if delta < 0:
        direction = "improved"
        message = (
            f"Security posture improved by {abs(delta)} points "
            f"({previous_grade} → {current_grade}) across {scan_count} scans."
        )
    elif delta > 0:
        direction = "regressed"
        message = (
            f"Security posture regressed by {delta} points "
            f"({previous_grade} → {current_grade}) — {current_stats.get('critical', 0)} critical findings."
        )
    else:
        direction = "unchanged"
        message = f"Security posture unchanged ({current_grade}) since last scan."

    return {
        "current_score":   current_score,
        "current_grade":   current_grade,
        "previous_score":  previous_score,
        "previous_grade":  previous_grade,
        "delta":           delta,
        "direction":       direction,
        "message":         message,
        "scan_count":      scan_count,
        "previous_scan_id": prev.get("scan_id"),
        "previous_scanned_at": prev.get("scanned_at"),
    }


def attach_trend(result_dict: dict, reports_dir: str) -> dict:
    """
    Takes a ScanResult as a dict (already serialised), computes trend,
    attaches it as result['trend']. Safe — never raises.
    """
    try:
        trend = compute_trend(
            current_scan_id = result_dict["scan_id"],
            current_stats   = result_dict.get("stats", {}),
            repo_name       = result_dict.get("repo", ""),
            reports_dir     = reports_dir,
        )
        result_dict["trend"] = trend
    except Exception as e:
        result_dict["trend"] = {"direction": "error", "message": str(e)}
    return result_dict
