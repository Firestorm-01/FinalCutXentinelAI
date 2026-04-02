"""
XentinelAI — MITRE ATT&CK Mapping Engine
Maps findings and attack chains to MITRE ATT&CK techniques and tactics.
Covers the full ATT&CK Enterprise matrix relevant to web/cloud/IAM findings.

Endpoint: GET /scan/{scan_id}/attack-map
Pure analysis — no external APIs, no network calls.
"""

from typing import Dict, Any, List


# ─────────────────────────────────────────────────────────────────────────────
# MITRE ATT&CK Tactics (kill chain phases)
# ─────────────────────────────────────────────────────────────────────────────

TACTICS = {
    "TA0001": "Initial Access",
    "TA0002": "Execution",
    "TA0003": "Persistence",
    "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",
    "TA0006": "Credential Access",
    "TA0007": "Discovery",
    "TA0008": "Lateral Movement",
    "TA0009": "Collection",
    "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    "TA0040": "Impact",
    "TA0043": "Reconnaissance",
}

TACTIC_ORDER = [
    "TA0043","TA0001","TA0002","TA0003","TA0004",
    "TA0005","TA0006","TA0007","TA0008","TA0009",
    "TA0010","TA0011","TA0040",
]


# ─────────────────────────────────────────────────────────────────────────────
# MITRE ATT&CK Techniques relevant to XentinelAI finding types
# ─────────────────────────────────────────────────────────────────────────────

TECHNIQUES = {
    "T1190": {
        "name":    "Exploit Public-Facing Application",
        "tactic":  "TA0001",
        "url":     "https://attack.mitre.org/techniques/T1190/",
        "summary": "Adversaries exploit weakness in internet-facing software to gain initial access.",
        "keywords": ["sql", "tainted-sql", "tainted-exec", "xss", "echoed", "injection",
                     "path-traversal", "tainted-filename", "ssrf", "cwe-89", "cwe-78",
                     "cwe-79", "cwe-22", "cwe-918"],
    },
    "T1059": {
        "name":    "Command and Scripting Interpreter",
        "tactic":  "TA0002",
        "url":     "https://attack.mitre.org/techniques/T1059/",
        "summary": "Adversaries abuse command interpreters to execute commands and scripts.",
        "keywords": ["exec", "tainted-exec", "subprocess", "shell", "cwe-78", "cwe-94"],
    },
    "T1078": {
        "name":    "Valid Accounts",
        "tactic":  "TA0001",
        "url":     "https://attack.mitre.org/techniques/T1078/",
        "summary": "Adversaries use compromised credentials to bypass access controls.",
        "keywords": ["hardcoded", "credential", "password", "secret", "cwe-798",
                     "cwe-259", "cwe-522", "brute"],
    },
    "T1552": {
        "name":    "Unsecured Credentials",
        "tactic":  "TA0006",
        "url":     "https://attack.mitre.org/techniques/T1552/",
        "summary": "Adversaries search for and find unsecured credentials in files and configs.",
        "keywords": ["hardcoded", "credential", "password", "secret", "api_key",
                     "cwe-798", "cwe-259", "cwe-321"],
    },
    "T1110": {
        "name":    "Brute Force",
        "tactic":  "TA0006",
        "url":     "https://attack.mitre.org/techniques/T1110/",
        "summary": "Adversaries use brute force to gain access to accounts.",
        "keywords": ["brute", "no-rate-limit", "cwe-307", "cwe-308"],
    },
    "T1083": {
        "name":    "File and Directory Discovery",
        "tactic":  "TA0007",
        "url":     "https://attack.mitre.org/techniques/T1083/",
        "summary": "Adversaries enumerate files and directories to find sensitive data.",
        "keywords": ["path-traversal", "tainted-filename", "directory-traversal",
                     "cwe-22", "cwe-918"],
    },
    "T1082": {
        "name":    "System Information Discovery",
        "tactic":  "TA0007",
        "url":     "https://attack.mitre.org/techniques/T1082/",
        "summary": "Adversaries gather system information to shape follow-on attacks.",
        "keywords": ["phpinfo", "debug", "information-disclosure", "cwe-200", "cwe-489"],
    },
    "T1213": {
        "name":    "Data from Information Repositories",
        "tactic":  "TA0009",
        "url":     "https://attack.mitre.org/techniques/T1213/",
        "summary": "Adversaries access data from repositories like databases.",
        "keywords": ["sql", "tainted-sql", "cwe-89"],
    },
    "T1048": {
        "name":    "Exfiltration Over Alternative Protocol",
        "tactic":  "TA0010",
        "url":     "https://attack.mitre.org/techniques/T1048/",
        "summary": "Adversaries exfiltrate data using protocols other than C2 channel.",
        "keywords": ["cors", "ssrf", "cwe-942", "cwe-918"],
    },
    "T1071": {
        "name":    "Application Layer Protocol",
        "tactic":  "TA0011",
        "url":     "https://attack.mitre.org/techniques/T1071/",
        "summary": "Adversaries use application layer protocols to blend C2 traffic.",
        "keywords": ["cors", "cwe-942"],
    },
    "T1499": {
        "name":    "Endpoint Denial of Service",
        "tactic":  "TA0040",
        "url":     "https://attack.mitre.org/techniques/T1499/",
        "summary": "Adversaries perform DoS attacks to degrade or block availability.",
        "keywords": ["no-rate-limit", "unrestricted", "cwe-400", "cwe-770"],
    },
    "T1565": {
        "name":    "Data Manipulation",
        "tactic":  "TA0040",
        "url":     "https://attack.mitre.org/techniques/T1565/",
        "summary": "Adversaries insert, delete, or manipulate data to influence outcomes.",
        "keywords": ["sql", "tainted-sql", "cwe-89"],
    },
    "T1098": {
        "name":    "Account Manipulation",
        "tactic":  "TA0003",
        "url":     "https://attack.mitre.org/techniques/T1098/",
        "summary": "Adversaries manipulate accounts to maintain access.",
        "keywords": ["iam", "wildcard", "privilege", "administrator", "cwe-269", "cwe-284"],
    },
    "T1548": {
        "name":    "Abuse Elevation Control Mechanism",
        "tactic":  "TA0004",
        "url":     "https://attack.mitre.org/techniques/T1548/",
        "summary": "Adversaries abuse mechanisms to elevate privileges.",
        "keywords": ["iam", "wildcard", "privilege-escalation", "administrator",
                     "cwe-269", "cwe-284", "cwe-285"],
    },
    "T1562": {
        "name":    "Impair Defenses",
        "tactic":  "TA0005",
        "url":     "https://attack.mitre.org/techniques/T1562/",
        "summary": "Adversaries impair defenses to avoid detection.",
        "keywords": ["no-logging", "debug", "cwe-223", "cwe-778"],
    },
    "T1530": {
        "name":    "Data from Cloud Storage",
        "tactic":  "TA0009",
        "url":     "https://attack.mitre.org/techniques/T1530/",
        "summary": "Adversaries access data from cloud storage objects.",
        "keywords": ["s3", "public-acl", "publicly-accessible", "bucket",
                     "ckv_aws_20", "ckv_aws_53", "ckv2_aws_6"],
    },
    "T1580": {
        "name":    "Cloud Infrastructure Discovery",
        "tactic":  "TA0007",
        "url":     "https://attack.mitre.org/techniques/T1580/",
        "summary": "Adversaries enumerate cloud infrastructure to identify resources.",
        "keywords": ["imds", "metadata", "ckv_aws_79", "cwe-200"],
    },
    "T1552.005": {
        "name":    "Cloud Instance Metadata API",
        "tactic":  "TA0006",
        "url":     "https://attack.mitre.org/techniques/T1552/005/",
        "summary": "Adversaries query the IMDS to obtain credentials and config.",
        "keywords": ["imds", "metadata", "http_tokens", "ckv_aws_79"],
    },
    "T1190.001": {
        "name":    "SQL Injection",
        "tactic":  "TA0001",
        "url":     "https://attack.mitre.org/techniques/T1190/",
        "summary": "Adversaries inject malicious SQL to manipulate database queries.",
        "keywords": ["tainted-sql", "sql-injection", "cwe-89"],
    },
    "T1059.004": {
        "name":    "Unix Shell",
        "tactic":  "TA0002",
        "url":     "https://attack.mitre.org/techniques/T1059/004/",
        "summary": "Adversaries abuse Unix shell commands to execute malicious code.",
        "keywords": ["tainted-exec", "shell=true", "subprocess", "cwe-78"],
    },
    "T1566": {
        "name":    "Phishing / Social Engineering via XSS",
        "tactic":  "TA0001",
        "url":     "https://attack.mitre.org/techniques/T1566/",
        "summary": "Adversaries use XSS to conduct phishing or steal credentials.",
        "keywords": ["xss", "echoed-request", "cross-site", "cwe-79"],
    },
    "T1136": {
        "name":    "Create Account",
        "tactic":  "TA0003",
        "url":     "https://attack.mitre.org/techniques/T1136/",
        "summary": "Adversaries create accounts to maintain access.",
        "keywords": ["iam", "cwe-269", "privilege"],
    },
    "T1619": {
        "name":    "Cloud Storage Object Discovery",
        "tactic":  "TA0007",
        "url":     "https://attack.mitre.org/techniques/T1619/",
        "summary": "Adversaries enumerate cloud storage to find sensitive data.",
        "keywords": ["s3", "bucket", "public-acl", "ckv_aws_20"],
    },
    "T1046": {
        "name":    "Network Service Discovery",
        "tactic":  "TA0007",
        "url":     "https://attack.mitre.org/techniques/T1046/",
        "summary": "Adversaries scan for open ports and services.",
        "keywords": ["security_group", "unrestricted", "0.0.0.0", "ckv_aws_23",
                     "ckv_aws_24", "cwe-668"],
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# Matching logic
# ─────────────────────────────────────────────────────────────────────────────

def _match_techniques(finding: Dict[str, Any]) -> List[str]:
    """Return list of technique IDs that match this finding."""
    title   = (finding.get("title")   or "").lower()
    rule_id = (finding.get("rule_id") or "").lower()
    cwe     = (finding.get("cwe")     or "").lower()
    desc    = (finding.get("description") or "").lower()
    combined = f"{title} {rule_id} {cwe} {desc}"

    matched = []
    for tech_id, tech in TECHNIQUES.items():
        for kw in tech["keywords"]:
            if kw.lower() in combined:
                matched.append(tech_id)
                break
    return matched


# ─────────────────────────────────────────────────────────────────────────────
# Kill chain builder
# ─────────────────────────────────────────────────────────────────────────────

def _build_kill_chain(tactic_ids: List[str]) -> List[Dict[str, Any]]:
    """
    Build an ordered kill chain from the set of detected tactics.
    Shows which phases of the ATT&CK matrix are covered.
    """
    detected = set(tactic_ids)
    chain = []
    for tactic_id in TACTIC_ORDER:
        chain.append({
            "tactic_id":   tactic_id,
            "tactic_name": TACTICS.get(tactic_id, "Unknown"),
            "detected":    tactic_id in detected,
        })
    return chain


# ─────────────────────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────────────────────

def build_attack_map(scan: Dict[str, Any]) -> Dict[str, Any]:
    """
    Map all findings to MITRE ATT&CK techniques and tactics.
    Returns structured attack map with kill chain coverage.
    """
    findings       = scan.get("findings", [])
    attack_chains  = scan.get("attack_chains", [])

    if not findings:
        return {
            "scan_id":    scan.get("scan_id", ""),
            "repo":       scan.get("repo", ""),
            "techniques": [],
            "tactics":    [],
            "kill_chain": [],
            "coverage":   0,
            "summary":    "No findings to map.",
        }

    # Map each finding to techniques
    technique_findings: Dict[str, List[str]] = {}   # tech_id → [finding_ids]
    finding_techniques: Dict[str, List[str]] = {}   # finding_id → [tech_ids]

    for f in findings:
        fid     = f.get("id", "")
        matched = _match_techniques(f)
        finding_techniques[fid] = matched
        for tech_id in matched:
            technique_findings.setdefault(tech_id, [])
            if fid not in technique_findings[tech_id]:
                technique_findings[tech_id].append(fid)

    # Build technique list
    techniques_out = []
    detected_tactics = set()

    for tech_id, finding_ids in technique_findings.items():
        tech = TECHNIQUES.get(tech_id, {})
        tactic_id = tech.get("tactic", "")
        detected_tactics.add(tactic_id)

        # Gather severity summary
        tech_findings = [f for f in findings if f.get("id") in finding_ids]
        sevs: Dict[str, int] = {}
        for f in tech_findings:
            s = f.get("severity", "UNKNOWN")
            sevs[s] = sevs.get(s, 0) + 1

        techniques_out.append({
            "technique_id":   tech_id,
            "technique_name": tech.get("name", ""),
            "tactic_id":      tactic_id,
            "tactic_name":    TACTICS.get(tactic_id, ""),
            "url":            tech.get("url", ""),
            "summary":        tech.get("summary", ""),
            "finding_count":  len(finding_ids),
            "finding_ids":    finding_ids,
            "severities":     sevs,
        })

    # Sort by tactic order then technique ID
    tactic_idx = {t: i for i, t in enumerate(TACTIC_ORDER)}
    techniques_out.sort(key=lambda t: (
        tactic_idx.get(t["tactic_id"], 99), t["technique_id"]
    ))

    # Build tactic summary
    tactics_out = []
    for tactic_id in TACTIC_ORDER:
        tactic_techs = [t for t in techniques_out if t["tactic_id"] == tactic_id]
        if tactic_techs:
            tactics_out.append({
                "tactic_id":       tactic_id,
                "tactic_name":     TACTICS.get(tactic_id, ""),
                "technique_count": len(tactic_techs),
                "techniques":      [t["technique_id"] for t in tactic_techs],
                "finding_count":   sum(t["finding_count"] for t in tactic_techs),
            })

    kill_chain    = _build_kill_chain(list(detected_tactics))
    detected_count = sum(1 for k in kill_chain if k["detected"])
    total_tactics  = len(TACTIC_ORDER)
    coverage_pct   = round(detected_count / total_tactics * 100)

    # Per-finding technique tags
    finding_tags = {
        fid: [
            {"id": tid, "name": TECHNIQUES[tid]["name"]}
            for tid in techs if tid in TECHNIQUES
        ]
        for fid, techs in finding_techniques.items()
        if techs
    }

    # Map attack chains to techniques
    chain_mappings = []
    for chain in attack_chains:
        chain_techs = set()
        for fid in chain.get("finding_ids", []):
            chain_techs.update(finding_techniques.get(fid, []))
        chain_mappings.append({
            "chain_id":    chain.get("id", ""),
            "chain_title": chain.get("title", ""),
            "risk_score":  chain.get("risk_score", 0),
            "techniques":  [
                {"id": tid, "name": TECHNIQUES[tid]["name"],
                 "tactic": TACTICS.get(TECHNIQUES[tid]["tactic"], "")}
                for tid in sorted(chain_techs) if tid in TECHNIQUES
            ],
        })

    return {
        "scan_id":       scan.get("scan_id", ""),
        "repo":          scan.get("repo", ""),
        "techniques":    techniques_out,
        "tactics":       tactics_out,
        "kill_chain":    kill_chain,
        "chain_mappings":chain_mappings,
        "finding_tags":  finding_tags,
        "coverage": {
            "tactics_detected": detected_count,
            "tactics_total":    total_tactics,
            "pct":              coverage_pct,
            "techniques_total": len(techniques_out),
        },
        "summary": (
            f"{len(techniques_out)} ATT&CK techniques detected across "
            f"{detected_count} of {total_tactics} tactics. "
            f"Kill chain coverage: {coverage_pct}%. "
            f"Highest risk phases: "
            + ", ".join(t["tactic_name"] for t in tactics_out[:3]) + "."
        ),
    }
