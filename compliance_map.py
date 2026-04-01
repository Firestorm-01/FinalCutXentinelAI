"""
XentinelAI — Compliance Mapping Engine
Maps findings to OWASP Top 10, CWE Top 25, PCI-DSS, and SOC 2.
Produces a compliance report showing which standards are violated and by how many findings.

Endpoint: GET /scan/{scan_id}/compliance
Drop-in: add endpoint to main.py only.
"""

from typing import Dict, Any, List


# ─────────────────────────────────────────────────────────────────────────────
# OWASP Top 10 (2021)
# ─────────────────────────────────────────────────────────────────────────────

OWASP_TOP10 = {
    "A01:2021": {
        "name": "Broken Access Control",
        "cwe":  ["CWE-22", "CWE-284", "CWE-285", "CWE-639"],
        "rules": ["path-traversal", "tainted-filename", "idor"],
    },
    "A02:2021": {
        "name": "Cryptographic Failures",
        "cwe":  ["CWE-311", "CWE-312", "CWE-319", "CWE-522", "CWE-798"],
        "rules": ["hardcoded", "secret", "password", "insecure-password"],
    },
    "A03:2021": {
        "name": "Injection",
        "cwe":  ["CWE-78", "CWE-79", "CWE-89", "CWE-94", "CWE-704"],
        "rules": ["sql", "tainted-sql", "tainted-exec", "subprocess", "xss",
                  "echoed-request", "raw-html", "injection"],
    },
    "A04:2021": {
        "name": "Insecure Design",
        "cwe":  ["CWE-209", "CWE-918"],
        "rules": ["phpinfo", "debug", "ssrf", "tainted-filename"],
    },
    "A05:2021": {
        "name": "Security Misconfiguration",
        "cwe":  ["CWE-16", "CWE-489", "CWE-668"],
        "rules": ["debug-enabled", "app-run", "cors", "publicly-accessible",
                  "public-acl", "imds", "security-group"],
    },
    "A06:2021": {
        "name": "Vulnerable and Outdated Components",
        "cwe":  ["CWE-1035", "CWE-937"],
        "rules": ["outdated", "vulnerable-dependency", "cve"],
    },
    "A07:2021": {
        "name": "Identification and Authentication Failures",
        "cwe":  ["CWE-287", "CWE-798", "CWE-307"],
        "rules": ["hardcoded", "brute", "auth", "session"],
    },
    "A08:2021": {
        "name": "Software and Data Integrity Failures",
        "cwe":  ["CWE-502", "CWE-829"],
        "rules": ["pickle", "deserialization", "unsafe-yaml"],
    },
    "A09:2021": {
        "name": "Security Logging and Monitoring Failures",
        "cwe":  ["CWE-117", "CWE-223", "CWE-778"],
        "rules": ["no-logging", "missing-log"],
    },
    "A10:2021": {
        "name": "Server-Side Request Forgery",
        "cwe":  ["CWE-918"],
        "rules": ["ssrf", "tainted-filename", "tainted-url"],
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# CWE Top 25 (2023)
# ─────────────────────────────────────────────────────────────────────────────

CWE_TOP25 = {
    "CWE-787": "Out-of-bounds Write",
    "CWE-79":  "Cross-site Scripting (XSS)",
    "CWE-89":  "SQL Injection",
    "CWE-416": "Use After Free",
    "CWE-78":  "OS Command Injection",
    "CWE-20":  "Improper Input Validation",
    "CWE-125": "Out-of-bounds Read",
    "CWE-22":  "Path Traversal",
    "CWE-352": "Cross-Site Request Forgery",
    "CWE-434": "Unrestricted File Upload",
    "CWE-862": "Missing Authorization",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-287": "Improper Authentication",
    "CWE-190": "Integer Overflow",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-77":  "Command Injection",
    "CWE-119": "Buffer Overflow",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-918": "Server-Side Request Forgery",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-362": "Race Condition",
    "CWE-269": "Improper Privilege Management",
    "CWE-94":  "Code Injection",
    "CWE-863": "Incorrect Authorization",
    "CWE-276": "Incorrect Default Permissions",
}


# ─────────────────────────────────────────────────────────────────────────────
# PCI-DSS v4.0 relevant requirements
# ─────────────────────────────────────────────────────────────────────────────

PCI_DSS = {
    "6.2.4": {
        "name": "Software development practices prevent common vulnerabilities",
        "cwe":  ["CWE-89", "CWE-78", "CWE-79", "CWE-94"],
        "rules": ["sql", "tainted-sql", "tainted-exec", "xss", "injection"],
    },
    "6.3.1": {
        "name": "Security vulnerabilities identified and addressed",
        "cwe":  ["CWE-79", "CWE-89", "CWE-78", "CWE-22", "CWE-918"],
        "rules": ["sql", "tainted-sql", "tainted-exec", "xss", "path-traversal",
                  "tainted-filename", "injection"],
    },
    "6.3.3": {
        "name": "All software components protected from known vulnerabilities",
        "cwe":  ["CWE-1035", "CWE-937"],
        "rules": ["outdated", "vulnerable-dependency"],
    },
    "2.2.1": {
        "name": "Configuration standards — no unnecessary defaults",
        "cwe":  ["CWE-16", "CWE-489"],
        "rules": ["debug", "phpinfo", "publicly-accessible", "public-acl",
                  "security-group", "imds"],
    },
    "8.3.2": {
        "name": "Strong cryptography for authentication credentials",
        "cwe":  ["CWE-798", "CWE-522", "CWE-312"],
        "rules": ["hardcoded", "secret", "password"],
    },
    "7.2.1": {
        "name": "Access control systems — least privilege",
        "cwe":  ["CWE-269", "CWE-284", "CWE-285"],
        "rules": ["iam", "wildcard", "privilege", "administrator"],
    },
    "10.2.1": {
        "name": "Audit logs capture security events",
        "cwe":  ["CWE-223", "CWE-778"],
        "rules": ["no-logging"],
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# SOC 2 Trust Service Criteria
# ─────────────────────────────────────────────────────────────────────────────

SOC2 = {
    "CC6.1": {
        "name": "Logical and physical access controls",
        "cwe":  ["CWE-284", "CWE-285", "CWE-269", "CWE-798"],
        "rules": ["iam", "wildcard", "hardcoded", "secret", "password",
                  "privilege", "administrator"],
    },
    "CC6.6": {
        "name": "Security threats from outside the boundaries",
        "cwe":  ["CWE-89", "CWE-78", "CWE-79", "CWE-22"],
        "rules": ["sql", "tainted-sql", "tainted-exec", "xss", "injection",
                  "path-traversal"],
    },
    "CC6.7": {
        "name": "Transmission and disclosure of information",
        "cwe":  ["CWE-311", "CWE-319", "CWE-918"],
        "rules": ["cors", "ssrf", "tainted-filename"],
    },
    "CC7.1": {
        "name": "Detection of security events",
        "cwe":  ["CWE-223", "CWE-778"],
        "rules": ["no-logging"],
    },
    "CC8.1": {
        "name": "Changes to infrastructure and software",
        "cwe":  ["CWE-16", "CWE-489"],
        "rules": ["debug", "phpinfo", "publicly-accessible"],
    },
    "A1.2": {
        "name": "Availability — environmental protection",
        "cwe":  ["CWE-400", "CWE-770"],
        "rules": ["security-group", "unrestricted", "public-acl"],
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# Matching logic
# ─────────────────────────────────────────────────────────────────────────────

def _matches(finding: Dict[str, Any], cwe_list: List[str], rule_keywords: List[str]) -> bool:
    """Check if a finding matches a compliance requirement."""
    f_cwe    = (finding.get("cwe")     or "").upper()
    f_rule   = (finding.get("rule_id") or "").lower()
    f_title  = (finding.get("title")   or "").lower()
    combined = f"{f_rule} {f_title}"

    # CWE match — check if finding's CWE starts with any listed CWE
    for cwe in cwe_list:
        if f_cwe.startswith(cwe.upper()):
            return True

    # Keyword match against rule_id and title
    for kw in rule_keywords:
        if kw.lower() in combined:
            return True

    return False


def _extract_cwe_id(cwe_str) -> str:
    """Extract 'CWE-XX' from a full CWE string like 'CWE-89: SQL Injection'."""
    if not cwe_str:
        return ""
    import re
    m = re.match(r"(CWE-\d+)", str(cwe_str).strip(), re.IGNORECASE)
    return m.group(1).upper() if m else ""


# ─────────────────────────────────────────────────────────────────────────────
# Core compliance mapper
# ─────────────────────────────────────────────────────────────────────────────

def build_compliance_report(scan: Dict[str, Any]) -> Dict[str, Any]:
    """
    Map all findings to compliance frameworks and return a structured report.
    """
    findings = scan.get("findings", [])
    if not findings:
        return {
            "scan_id": scan.get("scan_id", ""),
            "repo":    scan.get("repo", ""),
            "summary": "No findings to map.",
            "owasp":   {}, "cwe_top25": {}, "pci_dss": {}, "soc2": {},
            "overall": {},
        }

    # ── OWASP Top 10 ──
    owasp_results = {}
    for cat_id, cat in OWASP_TOP10.items():
        matched = [f for f in findings if _matches(f, cat["cwe"], cat["rules"])]
        owasp_results[cat_id] = {
            "name":        cat["name"],
            "violated":    len(matched) > 0,
            "finding_count": len(matched),
            "finding_ids": [f["id"] for f in matched],
            "severities":  _sev_summary(matched),
        }

    owasp_violated   = sum(1 for v in owasp_results.values() if v["violated"])
    owasp_total      = len(OWASP_TOP10)

    # ── CWE Top 25 ──
    cwe_results = {}
    for cwe_id, cwe_name in CWE_TOP25.items():
        matched = [f for f in findings
                   if _extract_cwe_id(f.get("cwe", "")) == cwe_id]
        if matched:
            cwe_results[cwe_id] = {
                "name":          cwe_name,
                "finding_count": len(matched),
                "finding_ids":   [f["id"] for f in matched],
                "severities":    _sev_summary(matched),
            }

    # ── PCI-DSS ──
    pci_results = {}
    for req_id, req in PCI_DSS.items():
        matched = [f for f in findings if _matches(f, req["cwe"], req["rules"])]
        pci_results[req_id] = {
            "name":          req["name"],
            "violated":      len(matched) > 0,
            "finding_count": len(matched),
            "finding_ids":   [f["id"] for f in matched],
            "severities":    _sev_summary(matched),
        }

    pci_violated = sum(1 for v in pci_results.values() if v["violated"])

    # ── SOC 2 ──
    soc2_results = {}
    for ctrl_id, ctrl in SOC2.items():
        matched = [f for f in findings if _matches(f, ctrl["cwe"], ctrl["rules"])]
        soc2_results[ctrl_id] = {
            "name":          ctrl["name"],
            "violated":      len(matched) > 0,
            "finding_count": len(matched),
            "finding_ids":   [f["id"] for f in matched],
            "severities":    _sev_summary(matched),
        }

    soc2_violated = sum(1 for v in soc2_results.values() if v["violated"])

    # ── Per-finding compliance tags ──
    finding_tags: Dict[str, Dict] = {}
    for f in findings:
        fid  = f["id"]
        tags = {
            "owasp":   [k for k, v in owasp_results.items()  if fid in v["finding_ids"]],
            "cwe_top25":[k for k, v in cwe_results.items()   if fid in v["finding_ids"]],
            "pci_dss": [k for k, v in pci_results.items()    if fid in v["finding_ids"]],
            "soc2":    [k for k, v in soc2_results.items()   if fid in v["finding_ids"]],
        }
        if any(tags.values()):
            finding_tags[fid] = tags

    # ── Overall posture ──
    overall = {
        "owasp":  {"violated": owasp_violated,  "total": owasp_total,
                   "pct": round(owasp_violated / owasp_total * 100)},
        "pci_dss":{"violated": pci_violated,    "total": len(PCI_DSS),
                   "pct": round(pci_violated / len(PCI_DSS) * 100)},
        "soc2":   {"violated": soc2_violated,   "total": len(SOC2),
                   "pct": round(soc2_violated / len(SOC2) * 100)},
        "cwe_top25_hit": len(cwe_results),
    }

    summary_parts = [
        f"OWASP Top 10: {owasp_violated}/{owasp_total} categories violated",
        f"PCI-DSS: {pci_violated}/{len(PCI_DSS)} requirements violated",
        f"SOC 2: {soc2_violated}/{len(SOC2)} criteria violated",
        f"CWE Top 25: {len(cwe_results)} of 25 weaknesses present",
    ]

    return {
        "scan_id":      scan.get("scan_id", ""),
        "repo":         scan.get("repo", ""),
        "scanned_at":   scan.get("scanned_at", ""),
        "summary":      "  ·  ".join(summary_parts),
        "overall":      overall,
        "owasp":        owasp_results,
        "cwe_top25":    cwe_results,
        "pci_dss":      pci_results,
        "soc2":         soc2_results,
        "finding_tags": finding_tags,
    }


def _sev_summary(findings: List[Dict]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for f in findings:
        s = f.get("severity", "UNKNOWN")
        counts[s] = counts.get(s, 0) + 1
    return counts