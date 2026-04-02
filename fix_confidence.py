"""
XentinelAI — Fix Confidence Scorer
Rates each AI-generated fix 0-100 based on completeness, context accuracy,
and fix type. Adds a confidence badge to each finding with fixed_code.

Scores:
  80-100  High Confidence   — complete, context-aware fix, safe to apply with review
  50-79   Medium Confidence — partial or generic fix, needs careful review
  0-49    Low Confidence    — incomplete or vague, manual implementation required

Called automatically during scan enrichment — no separate endpoint needed.
Also exposed as: GET /scan/{scan_id}/confidence
"""

import re
from typing import Dict, Any, List, Optional


# ─────────────────────────────────────────────────────────────────────────────
# Scoring criteria
# ─────────────────────────────────────────────────────────────────────────────

# Fix types ordered from highest to lowest inherent confidence
FIX_TYPE_SCORES: List[tuple] = [
    # (pattern_in_fix, score, label)
    (r"prepare\s*\(|bind_param|parameteriz|placeholder",  25, "parameterised_query"),
    (r"escapeshellarg|escapeshellcmd",                     25, "shell_escape"),
    (r"htmlentities|htmlspecialchars|DOMPurify|sanitize",  22, "output_encoding"),
    (r"os\.path\.basename|os\.path\.join|realpath",        22, "path_sanitisation"),
    (r"os\.environ|getenv|process\.env|ENV\[",             20, "env_var_replacement"),
    (r"http_tokens\s*=\s*['\"]required['\"]",              25, "imds_hardening"),
    (r"publicly_accessible\s*=\s*false",                   25, "infra_hardening"),
    (r"block_public_acls\s*=\s*true",                      25, "infra_hardening"),
    (r"storage_encrypted\s*=\s*true",                      22, "encryption_enabled"),
    (r"cidr_blocks\s*=\s*\[\"(?!0\.0\.0\.0)",             20, "network_restriction"),
    (r'Action.*(?:logs:|s3:|ec2:Describe)',                 18, "least_privilege"),
    (r"debug\s*=\s*False|debug\s*=\s*false",               15, "debug_disabled"),
    (r"filter_var|preg_replace|sanitize",                  15, "input_validation"),
]

# Penalise vague or incomplete fixes
PENALTY_PATTERNS: List[tuple] = [
    (r"review manually|manual",          -15, "manual_required"),
    (r"TODO|FIXME|placeholder",          -20, "placeholder_present"),
    (r"\.\.\.",                          -10, "truncated_code"),
    (r"example\.com|your[-_]?domain",    -10, "placeholder_url"),
    (r"your[-_]?password|YOUR[-_]?KEY",  -15, "placeholder_secret"),
    (r"^\s*#.*$",                         -5, "comment_only"),
]

# Reward context-awareness — fix references actual file/variable names
CONTEXT_BONUS = 15

# Reward completeness — fix is a full replacement, not a snippet
COMPLETENESS_BONUS = 10

# Base score before any adjustments
BASE_SCORE = 40


# ─────────────────────────────────────────────────────────────────────────────
# Scorer
# ─────────────────────────────────────────────────────────────────────────────

def _score_fix(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Score a single finding's fixed_code. Returns scoring breakdown."""
    fixed_code  = (finding.get("fixed_code")  or "").strip()
    fix_hint    = (finding.get("fix_hint")     or "").strip()
    description = (finding.get("description") or "").strip()
    title       = (finding.get("title")        or "").strip()
    file_path   = (finding.get("file")         or "").strip()

    if not fixed_code:
        return {
            "score":      0,
            "grade":      "none",
            "label":      "No Fix Available",
            "breakdown":  [],
            "confidence": "none",
        }

    score      = BASE_SCORE
    breakdown  = []
    fix_type   = "generic"

    # ── Fix type score ──
    combined = f"{fixed_code} {fix_hint}".lower()
    for pattern, pts, label in FIX_TYPE_SCORES:
        if re.search(pattern, combined, re.IGNORECASE):
            score   += pts
            fix_type = label
            breakdown.append({"reason": f"Fix type: {label}", "points": pts})
            break   # take only the highest-matching type

    # ── Penalties ──
    for pattern, pts, label in PENALTY_PATTERNS:
        if re.search(pattern, fixed_code, re.IGNORECASE | re.MULTILINE):
            score += pts
            breakdown.append({"reason": f"Penalty: {label}", "points": pts})

    # ── Context-awareness bonus ──
    # Check if fixed_code references variable names or identifiers from the description
    context_words = _extract_identifiers(description + " " + title)
    fix_words     = _extract_identifiers(fixed_code)
    overlap       = context_words & fix_words
    if len(overlap) >= 2:
        score += CONTEXT_BONUS
        breakdown.append({"reason": "Context-aware: references actual code identifiers", "points": CONTEXT_BONUS})
    elif len(overlap) == 1:
        score += CONTEXT_BONUS // 2
        breakdown.append({"reason": "Partially context-aware", "points": CONTEXT_BONUS // 2})

    # ── Completeness bonus ──
    lines = [l for l in fixed_code.splitlines() if l.strip() and not l.strip().startswith("#")]
    if len(lines) >= 2:
        score += COMPLETENESS_BONUS
        breakdown.append({"reason": "Multi-line complete fix", "points": COMPLETENESS_BONUS})

    # ── Length sanity check ──
    # Very short fixes on complex vulns are suspicious
    if len(fixed_code) < 20 and finding.get("severity") in ("CRITICAL", "HIGH"):
        score -= 10
        breakdown.append({"reason": "Very short fix for critical/high severity", "points": -10})

    # ── Clamp ──
    score = max(0, min(100, score))

    grade, label, confidence = _grade(score)

    return {
        "score":      score,
        "grade":      grade,
        "label":      label,
        "confidence": confidence,
        "fix_type":   fix_type,
        "breakdown":  breakdown,
    }


def _extract_identifiers(text: str) -> set:
    """Extract meaningful code identifiers (variable names, function names)."""
    # Find camelCase, snake_case, and $ prefixed identifiers
    tokens = re.findall(r"\b[a-z][a-z0-9_]{2,}\b|\b[A-Z][A-Za-z0-9]{2,}\b", text)
    # Filter out common English words
    stopwords = {
        "the", "this", "that", "with", "from", "into", "have", "been",
        "will", "can", "for", "are", "use", "using", "used", "user",
        "code", "data", "file", "path", "string", "value", "input",
        "sql", "query", "function", "method", "class", "variable",
    }
    return {t.lower() for t in tokens if t.lower() not in stopwords}


def _grade(score: int) -> tuple:
    if score >= 80:
        return "high",   "High Confidence",   "high"
    if score >= 50:
        return "medium", "Review Recommended", "medium"
    return "low",    "Manual Review Required", "low"


# ─────────────────────────────────────────────────────────────────────────────
# Enrich findings in-place
# ─────────────────────────────────────────────────────────────────────────────

def enrich_with_confidence(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Add confidence scores to all findings with fixed_code.
    Modifies findings in-place and returns the list.
    """
    for f in findings:
        if f.get("fixed_code"):
            result = _score_fix(f)
            f["fix_confidence"]       = result["score"]
            f["fix_confidence_grade"] = result["grade"]
            f["fix_confidence_label"] = result["label"]
            f["fix_type"]             = result.get("fix_type", "generic")
        else:
            f["fix_confidence"]       = 0
            f["fix_confidence_grade"] = "none"
            f["fix_confidence_label"] = "No Fix Available"
            f["fix_type"]             = "none"
    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Public entry point (for endpoint)
# ─────────────────────────────────────────────────────────────────────────────

def build_confidence_report(scan: Dict[str, Any]) -> Dict[str, Any]:
    """
    Score all findings with fixed_code in a scan.
    Returns structured confidence report.
    """
    findings = scan.get("findings", [])
    scored   = []

    for f in findings:
        result = _score_fix(f)
        scored.append({
            "finding_id":   f.get("id", ""),
            "title":        f.get("title", ""),
            "severity":     f.get("severity", ""),
            "file":         f.get("file", ""),
            "has_fix":      bool(f.get("fixed_code")),
            "score":        result["score"],
            "grade":        result["grade"],
            "label":        result["label"],
            "confidence":   result["confidence"],
            "fix_type":     result.get("fix_type", "generic"),
            "breakdown":    result["breakdown"],
        })

    with_fix    = [s for s in scored if s["has_fix"]]
    high_conf   = [s for s in with_fix if s["grade"] == "high"]
    medium_conf = [s for s in with_fix if s["grade"] == "medium"]
    low_conf    = [s for s in with_fix if s["grade"] == "low"]
    avg_score   = round(sum(s["score"] for s in with_fix) / max(1, len(with_fix)))

    return {
        "scan_id":        scan.get("scan_id", ""),
        "repo":           scan.get("repo", ""),
        "total_findings": len(findings),
        "with_fix":       len(with_fix),
        "high_confidence":   len(high_conf),
        "medium_confidence": len(medium_conf),
        "low_confidence":    len(low_conf),
        "average_score":  avg_score,
        "findings":       scored,
        "summary": (
            f"{len(with_fix)} of {len(findings)} findings have AI-generated fixes. "
            f"{len(high_conf)} high confidence (safe to apply), "
            f"{len(medium_conf)} need review, "
            f"{len(low_conf)} require manual implementation."
        ),
    }
