"""
XentinelAI — Multi-Repo Portfolio Scanner
Scans multiple GitHub repos in parallel and produces an org-wide security report.

Endpoint: POST /portfolio/scan
Body: {
  "repos": ["https://github.com/org/repo1", "https://github.com/org/repo2"],
  "skip_ai": true   // recommended true to conserve tokens
}

Drop-in: add endpoint to main.py only.
"""

import os
import uuid
import json
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List, Optional
from collections import defaultdict


# ─────────────────────────────────────────────────────────────────────────────
# Per-repo scan runner (reuses existing pipeline)
# ─────────────────────────────────────────────────────────────────────────────

def _scan_one_repo(
    github_url: str,
    upload_dir: str,
    reports_dir: str,
    skip_ai: bool,
) -> Dict[str, Any]:
    """
    Clone, scan, and return result dict for a single repo.
    Returns error dict on failure — never raises.
    """
    repo_path = None
    repo_name = github_url.rstrip("/").split("/")[-1]

    try:
        from ingest import clone_github, cleanup
        repo_path = clone_github(github_url, upload_dir)

        # Import here to avoid circular at module level
        from scanners import code as code_scanner
        from scanners import iac  as iac_scanner
        from scanners import iam  as iam_scanner
        from models import ScanResult
        from ai_engine import enrich_scan
        from risk_trend import attach_trend

        result = ScanResult(repo=repo_name)
        try:
            result.findings.extend(code_scanner.run(repo_path))
        except Exception as e:
            print(f"[PORTFOLIO] Code scan error {repo_name}: {e}")
        try:
            result.findings.extend(iac_scanner.run(repo_path))
        except Exception as e:
            print(f"[PORTFOLIO] IaC scan error {repo_name}: {e}")
        try:
            result.findings.extend(iam_scanner.run(repo_path))
        except Exception as e:
            print(f"[PORTFOLIO] IAM scan error {repo_name}: {e}")

        if not skip_ai and result.findings:
            try:
                result = enrich_scan(result, repo_path)
            except Exception as e:
                print(f"[PORTFOLIO] AI enrichment error {repo_name}: {e}")

        result.compute_stats()
        result_dict = json.loads(result.model_dump_json())
        result_dict["repo_url"]  = github_url
        result_dict["repo_path"] = repo_path
        result_dict = attach_trend(result_dict, reports_dir)

        # Save individual report
        report_path = os.path.join(reports_dir, f"{result.scan_id}.json")
        try:
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(result_dict, f, indent=2)
        except OSError:
            pass

        print(f"[PORTFOLIO] Done: {repo_name} — {result.stats.get('total', 0)} findings")
        return result_dict

    except Exception as e:
        print(f"[PORTFOLIO] Failed: {repo_name} — {type(e).__name__}: {e}")
        return {
            "error":    str(e),
            "repo":     repo_name,
            "repo_url": github_url,
            "scan_id":  str(uuid.uuid4()),
            "findings": [],
            "attack_chains": [],
            "stats":    {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
        }
    finally:
        if repo_path:
            try:
                from ingest import cleanup
                cleanup(repo_path)
            except Exception:
                pass


# ─────────────────────────────────────────────────────────────────────────────
# Systemic issue detector
# ─────────────────────────────────────────────────────────────────────────────

def _find_systemic_issues(repo_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Find vulnerability patterns that appear across multiple repos.
    A systemic issue is a rule_id that appears in 2+ repos.
    """
    # rule_id → list of (repo_name, finding)
    rule_repos: Dict[str, List] = defaultdict(list)

    for result in repo_results:
        if result.get("error"):
            continue
        repo = result.get("repo", "unknown")
        for f in result.get("findings", []):
            key = f.get("rule_id") or f.get("title", "unknown")
            rule_repos[key].append({
                "repo":     repo,
                "finding":  f,
            })

    systemic = []
    for rule_id, occurrences in rule_repos.items():
        repos_affected = list(dict.fromkeys(o["repo"] for o in occurrences))
        if len(repos_affected) < 2:
            continue

        # Get a representative finding for fix info
        rep = occurrences[0]["finding"]
        systemic.append({
            "rule_id":        rule_id,
            "title":          rep.get("title", ""),
            "repos_affected": repos_affected,
            "repo_count":     len(repos_affected),
            "total_occurrences": len(occurrences),
            "severity":       rep.get("severity", ""),
            "fix_hint":       rep.get("fix_hint", ""),
            "fixed_code":     rep.get("fixed_code"),
            "message": (
                f"{len(repos_affected)} repos share this "
                f"{rep.get('severity','').lower()} vulnerability — "
                f"fix once and apply the same patch across all repos."
            ),
        })

    # Sort by number of repos affected descending
    systemic.sort(key=lambda x: (x["repo_count"], x["total_occurrences"]), reverse=True)
    return systemic


# ─────────────────────────────────────────────────────────────────────────────
# Score helper (same formula as trend_api)
# ─────────────────────────────────────────────────────────────────────────────

def _score(stats: Dict) -> int:
    total    = stats.get("total", 0)
    critical = stats.get("critical", 0)
    high     = stats.get("high", 0)
    medium   = stats.get("medium", 0)
    if total == 0:
        return 100
    penalty = (critical * 10) + (high * 4) + (medium * 1)
    return max(0, 100 - penalty)


def _grade(score: int) -> str:
    if score >= 90: return "A"
    if score >= 75: return "B"
    if score >= 60: return "C"
    if score >= 40: return "D"
    return "F"


# ─────────────────────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────────────────────

def run_portfolio_scan(
    repo_urls:   List[str],
    upload_dir:  str,
    reports_dir: str,
    skip_ai:     bool = True,
    max_workers: int  = 3,
) -> Dict[str, Any]:
    """
    Scan multiple repos in parallel.
    Returns a portfolio-level report with per-repo results and systemic issues.

    max_workers: parallel threads (keep ≤3 to avoid rate limits)
    skip_ai: recommended True for portfolio scans to conserve tokens
    """
    if not repo_urls:
        return {"error": "No repositories provided."}

    # Cap at 10 repos per portfolio scan
    repo_urls = repo_urls[:10]

    portfolio_id = str(uuid.uuid4())
    started_at   = datetime.now(timezone.utc).isoformat()

    print(f"[PORTFOLIO] Starting scan of {len(repo_urls)} repos (skip_ai={skip_ai})")

    # ── Parallel scan ──
    repo_results: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_scan_one_repo, url, upload_dir, reports_dir, skip_ai): url
            for url in repo_urls
        }
        for future in as_completed(futures):
            try:
                result = future.result(timeout=300)
                repo_results.append(result)
            except Exception as e:
                url = futures[future]
                repo_results.append({
                    "error":    str(e),
                    "repo":     url.rstrip("/").split("/")[-1],
                    "repo_url": url,
                    "scan_id":  str(uuid.uuid4()),
                    "findings": [],
                    "attack_chains": [],
                    "stats":    {"total": 0, "critical": 0, "high": 0,
                                 "medium": 0, "low": 0},
                })

    # ── Per-repo rankings ──
    repo_summaries = []
    for r in repo_results:
        stats = r.get("stats", {})
        sc    = _score(stats)
        repo_summaries.append({
            "scan_id":       r.get("scan_id", ""),
            "repo":          r.get("repo", ""),
            "repo_url":      r.get("repo_url", ""),
            "score":         sc,
            "grade":         _grade(sc),
            "total":         stats.get("total", 0),
            "critical":      stats.get("critical", 0),
            "high":          stats.get("high", 0),
            "medium":        stats.get("medium", 0),
            "attack_chains": len(r.get("attack_chains", [])),
            "error":         r.get("error"),
        })

    # Sort worst → best (ascending score)
    repo_summaries.sort(key=lambda x: x["score"])

    # ── Org-wide stats ──
    successful = [r for r in repo_results if not r.get("error")]
    total_findings  = sum(r.get("stats", {}).get("total",    0) for r in successful)
    total_critical  = sum(r.get("stats", {}).get("critical", 0) for r in successful)
    total_high      = sum(r.get("stats", {}).get("high",     0) for r in successful)
    total_chains    = sum(len(r.get("attack_chains", []))       for r in successful)
    avg_score       = round(sum(s["score"] for s in repo_summaries if not s.get("error"))
                            / max(1, len(successful)))

    # ── Systemic issues ──
    systemic = _find_systemic_issues(repo_results)

    # ── Save portfolio report ──
    portfolio_report = {
        "portfolio_id":   portfolio_id,
        "scanned_at":     started_at,
        "repos_requested":len(repo_urls),
        "repos_scanned":  len(successful),
        "repos_failed":   len(repo_urls) - len(successful),
        "org_stats": {
            "total_findings":  total_findings,
            "total_critical":  total_critical,
            "total_high":      total_high,
            "total_chains":    total_chains,
            "average_score":   avg_score,
            "average_grade":   _grade(avg_score),
        },
        "repo_rankings":  repo_summaries,
        "systemic_issues":systemic,
        "scan_ids":       [r.get("scan_id") for r in repo_results],
        "summary": (
            f"{len(successful)}/{len(repo_urls)} repos scanned. "
            f"Org-wide: {total_critical} critical, {total_high} high findings. "
            f"Average security score: {avg_score}/100 ({_grade(avg_score)}). "
            f"{len(systemic)} systemic vulnerabilities shared across multiple repos."
        ),
    }

    # Persist portfolio report
    portfolio_path = os.path.join(reports_dir, f"portfolio-{portfolio_id[:8]}.json")
    try:
        with open(portfolio_path, "w", encoding="utf-8") as f:
            json.dump(portfolio_report, f, indent=2)
    except OSError:
        pass

    return portfolio_report
