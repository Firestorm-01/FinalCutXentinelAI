"""
XentinelAI — Natural Language Query Engine
Answers plain English questions about a scan result using Groq/Bedrock.
Strictly grounded — only answers from actual scan data, never hallucinates.
Includes roadmap data in context so effort/priority questions work correctly.

Endpoint: POST /scan/{scan_id}/ask
Body: {"question": "which files have the most vulnerabilities?"}

Drop-in: no existing files changed except main.py (one endpoint added).
"""

import json
from typing import Dict, Any


# ─────────────────────────────────────────────────────────────────────────────
# Effort map — mirrors remediation_roadmap.py so NLP can answer effort Qs
# ─────────────────────────────────────────────────────────────────────────────

EFFORT_MAP = {
    "sql":            "15–30 min — replace string interpolation with prepared statements",
    "exec":           "15–30 min — wrap user input with escapeshellarg() or list args",
    "xss":            "10–20 min — escape output with htmlentities() or template engine",
    "phpinfo":        "5 min — remove or gate phpinfo() calls behind auth check",
    "cors":           "10 min — replace wildcard origin with specific allowed domains",
    "hardcoded":      "20–40 min — move credentials to environment variables or secrets manager",
    "path":           "15–25 min — validate and sanitise filename inputs, use basename()",
    "filename":       "15–25 min — validate and sanitise filename inputs, use basename()",
    "iam":            "30–60 min — replace wildcard actions with least-privilege policy",
    "imds":           "5 min — set http_tokens = required in metadata_options block",
    "public":         "10 min — set publicly_accessible = false / ACL to private",
    "security_group": "15 min — restrict CIDR blocks to known IP ranges",
}


def _estimate_effort(title: str, rule_id: str) -> str:
    combined = f"{title} {rule_id}".lower()
    for key, val in EFFORT_MAP.items():
        if key in combined:
            return val
    return "20–40 min — review and apply the recommended fix"


# ─────────────────────────────────────────────────────────────────────────────
# Scan context builder
# ─────────────────────────────────────────────────────────────────────────────

def _build_context(scan: Dict[str, Any]) -> str:
    """
    Build a compact, structured summary of the scan for the AI prompt.
    Includes effort estimates per finding type so effort/priority questions
    can be answered accurately.
    """
    findings = scan.get("findings", [])
    chains   = scan.get("attack_chains", [])
    stats    = scan.get("stats", {})
    repo     = scan.get("repo", "unknown")
    scanned  = scan.get("scanned_at", "")[:10]

    # File → findings mapping
    file_map: Dict[str, list] = {}
    for f in findings:
        fp = f.get("file") or "unknown"
        file_map.setdefault(fp, []).append(f)

    top_files = sorted(file_map.items(), key=lambda x: len(x[1]), reverse=True)[:10]

    # Unique rule types with counts
    rule_counts: Dict[str, int] = {}
    for f in findings:
        key = f.get("rule_id") or f.get("title", "unknown")
        rule_counts[key] = rule_counts.get(key, 0) + 1

    top_rules = sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    lines = [
        f"REPOSITORY: {repo}",
        f"SCAN DATE: {scanned}",
        f"SCAN ID: {scan.get('scan_id', '')}",
        "",
        "STATISTICS:",
        f"  Total findings: {stats.get('total', 0)}",
        f"  Critical: {stats.get('critical', 0)}",
        f"  High: {stats.get('high', 0)}",
        f"  Medium: {stats.get('medium', 0)}",
        f"  Low: {stats.get('low', 0)}",
        f"  Attack chains: {len(chains)}",
        f"  Domains: {json.dumps(stats.get('by_domain', {}))}",
        "",
        "TOP FILES BY FINDING COUNT:",
    ]

    for fp, flist in top_files:
        sevs  = [f.get("severity", "?") for f in flist]
        crit  = sevs.count("CRITICAL")
        high  = sevs.count("HIGH")
        lines.append(f"  {fp}: {len(flist)} findings ({crit} critical, {high} high)")

    lines += ["", "TOP VULNERABILITY TYPES (with effort estimate):"]
    for rule, count in top_rules:
        # Get a sample finding for this rule to estimate effort
        sample = next((f for f in findings
                       if (f.get("rule_id") or f.get("title")) == rule), {})
        effort = _estimate_effort(sample.get("title", ""), sample.get("rule_id", ""))
        lines.append(f"  {rule}: {count} occurrence(s) — fix effort: {effort}")

    lines += ["", "ATTACK CHAINS:"]
    if chains:
        for c in chains:
            lines.append(
                f"  [{c.get('risk_score', 0)}/100] {c.get('title', '')}: "
                f"{c.get('description', '')[:120]}"
            )
            lines.append(f"    Remediation: {c.get('remediation', '')}")
    else:
        lines.append("  None detected")

    # Effort summary for critical findings
    lines += ["", "EFFORT SUMMARY — CRITICAL FINDINGS:"]
    seen_rules: set = set()
    total_min = 0
    total_max = 0

    import re as _re
    for f in findings:
        if f.get("severity") != "CRITICAL":
            continue
        key = f.get("rule_id") or f.get("title", "")
        if key in seen_rules:
            continue
        seen_rules.add(key)
        effort = _estimate_effort(f.get("title", ""), f.get("rule_id", ""))
        count  = rule_counts.get(key, 1)
        lines.append(f"  [{f.get('severity')}] {f.get('title','')} × {count}: {effort}")
        nums = _re.findall(r"\d+", effort)
        if len(nums) >= 2:
            total_min += int(nums[0])
            total_max += int(nums[1])
        elif len(nums) == 1:
            total_min += int(nums[0])
            total_max += int(nums[0])

    if total_min > 0:
        if total_min >= 60:
            h_min, h_max = total_min // 60, total_max // 60
            m_min, m_max = total_min % 60, total_max % 60
            lines.append(f"  TOTAL ESTIMATED EFFORT (critical): ~{h_min}–{h_max}h {m_min}–{m_max}min")
        else:
            lines.append(f"  TOTAL ESTIMATED EFFORT (critical): ~{total_min}–{total_max} min")

    lines += ["", "ALL FINDINGS (id | severity | title | file:line | fix_hint):"]
    for f in findings:
        file_str = f.get("file") or "—"
        line_str = f":{f['line']}" if f.get("line") else ""
        fix      = (f.get("fix_hint") or "—")[:80]
        lines.append(
            f"  {f.get('id','')} | {f.get('severity','')} | "
            f"{f.get('title','')} | {file_str}{line_str} | {fix}"
        )

    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Query system prompt
# ─────────────────────────────────────────────────────────────────────────────

QUERY_SYSTEM = """You are XentinelAI's security analyst assistant.
You answer questions about a specific security scan result.

STRICT RULES:
- Answer ONLY from the scan data provided. Never invent findings, files, or statistics.
- Effort estimates ARE provided in the context under "EFFORT SUMMARY" and "TOP VULNERABILITY TYPES" — use these to answer effort questions.
- If the answer is not in the scan data, say so clearly.
- Be concise and precise. Use bullet points for lists.
- When mentioning findings, include severity and file.
- When giving effort estimates, use the values from the EFFORT SUMMARY section.
- Format numbers clearly. Use "critical", "high" etc in lowercase.
- Do not add disclaimers or caveats unless genuinely relevant.
- Respond in plain text, no markdown headers, no code blocks unless showing a fix."""


# ─────────────────────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────────────────────

def answer_question(scan: Dict[str, Any], question: str) -> Dict[str, Any]:
    """
    Answer a natural language question about a scan result.
    Uses Groq (with Bedrock fallback) via the existing call_ai function.
    Returns {"answer": str, "question": str, "scan_id": str, "repo": str}
    """
    if not question or not question.strip():
        return {
            "answer":   "Please ask a question about the scan.",
            "question": question,
            "scan_id":  scan.get("scan_id", ""),
            "repo":     scan.get("repo", ""),
        }

    question = question.strip()[:500]
    context  = _build_context(scan)

    prompt = (
        f"Here is the security scan data:\n\n"
        f"{context}\n\n"
        f"Question: {question}\n\n"
        f"Answer based strictly on the scan data above:"
    )

    try:
        from ai_engine import call_ai
        answer = call_ai(prompt, QUERY_SYSTEM, max_tokens=600)
        answer = answer.strip()
    except Exception as e:
        answer = f"Query engine unavailable: {type(e).__name__}: {e}"

    return {
        "answer":   answer,
        "question": question,
        "scan_id":  scan.get("scan_id", ""),
        "repo":     scan.get("repo", ""),
    }