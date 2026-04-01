"""
XentinelAI — Remediation Roadmap
Generates a dependency-aware, prioritised fix order from a scan result.

Logic:
  1. Group findings by rule/type to avoid duplicate fix steps
  2. Build dependency edges: if finding B's vulnerability class typically
     requires finding A to exist first (e.g. info disclosure → SQLi),
     A must be fixed before B
  3. Topological sort → numbered checklist with reasoning
  4. Each step includes: what to fix, why now, which files, estimated effort

Endpoint: GET /scan/{scan_id}/roadmap
Drop-in: no existing files changed except main.py (one endpoint added).
"""

from typing import Dict, Any, List, Tuple, Set
from collections import defaultdict, deque


# ─────────────────────────────────────────────────────────────────────────────
# Severity and effort weights
# ─────────────────────────────────────────────────────────────────────────────

SEV_WEIGHT = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# Estimated fix effort in minutes per rule type
EFFORT_MAP = {
    "sql":           ("15–30 min", "Replace string interpolation with prepared statements"),
    "exec":          ("15–30 min", "Wrap user input with escapeshellarg() or pass as list arg"),
    "xss":           ("10–20 min", "Escape output with htmlentities() or a template engine"),
    "phpinfo":       ("5 min",     "Remove or gate phpinfo() calls behind auth"),
    "cors":          ("10 min",    "Replace wildcard origin with specific allowed domains"),
    "hardcoded":     ("20–40 min", "Move credentials to environment variables or secrets manager"),
    "path":          ("15–25 min", "Validate and sanitise filename inputs, use basename()"),
    "filename":      ("15–25 min", "Validate and sanitise filename inputs, use basename()"),
    "iam":           ("30–60 min", "Replace wildcard actions with least-privilege policy"),
    "imds":          ("5 min",     "Set http_tokens = required in metadata_options block"),
    "public":        ("10 min",    "Set publicly_accessible = false / ACL to private"),
    "security_group":("15 min",   "Restrict CIDR blocks to known IP ranges"),
    "default":       ("20–40 min", "Review and apply the recommended fix"),
}


def _effort(rule_id: str, title: str) -> Tuple[str, str]:
    combined = f"{rule_id} {title}".lower()
    for key, val in EFFORT_MAP.items():
        if key in combined:
            return val
    return EFFORT_MAP["default"]


# ─────────────────────────────────────────────────────────────────────────────
# Dependency rules
# Defines which vulnerability CLASSES must be fixed before others.
# Format: (prerequisite_class, dependent_class, reason)
# ─────────────────────────────────────────────────────────────────────────────

DEPENDENCY_RULES: List[Tuple[str, str, str]] = [
    # Info disclosure enables other attacks
    ("INFO_DISCLOSURE", "DB",      "Information disclosure reveals DB structure — fix first to remove attacker reconnaissance advantage"),
    ("INFO_DISCLOSURE", "RCE",     "phpinfo/debug pages reveal server config used to craft RCE payloads"),
    ("INFO_DISCLOSURE", "PATH",    "Exposed paths enable targeted traversal — remove disclosure first"),
    # Credentials enable cloud/IAM attacks
    ("CRED",            "CLOUD",   "Hardcoded credentials directly enable cloud API access — fix credentials first"),
    ("CRED",            "PRIVESC", "Exposed credentials can be used to escalate via IAM — rotate and remove first"),
    # SQLi chains to RCE in some stacks
    ("DB",              "RCE",     "SQL injection can lead to command execution via stored procedures or file writes — fix SQLi first"),
    # Network exposure enables brute force of auth
    ("NET",             "CRED",    "Open management ports expose credential endpoints — restrict network access first"),
    # CORS enables XSS exploitation
    ("CORS",            "XSS",     "CORS wildcard allows cross-origin script injection — fix CORS before XSS to limit blast radius"),
]

# Maps finding signals to vulnerability class
def _vuln_class(finding: Dict[str, Any]) -> str:
    title   = (finding.get("title")   or "").lower()
    rule_id = (finding.get("rule_id") or "").lower()
    cwe     = (finding.get("cwe")     or "").lower()
    combined = f"{title} {rule_id} {cwe}"

    if any(x in combined for x in ["phpinfo", "information disclosure", "cwe-200", "debug", "echoed"]):
        return "INFO_DISCLOSURE"
    if any(x in combined for x in ["sql", "tainted-sql", "cwe-89"]):
        return "DB"
    if any(x in combined for x in ["exec", "tainted-exec", "subprocess", "shell", "cwe-78", "cwe-94"]):
        return "RCE"
    if any(x in combined for x in ["xss", "cross-site", "cwe-79"]):
        return "XSS"
    if any(x in combined for x in ["cors", "cwe-942"]):
        return "CORS"
    if any(x in combined for x in ["path", "traversal", "filename", "tainted-filename", "cwe-22", "cwe-918"]):
        return "PATH"
    if any(x in combined for x in ["hardcoded", "secret", "credential", "password", "cwe-798", "cwe-259"]):
        return "CRED"
    if any(x in combined for x in ["iam", "privilege", "escalat", "wildcard", "administrator"]):
        return "PRIVESC"
    if any(x in combined for x in ["publicly_accessible", "public.ip", "s3", "bucket", "imds", "metadata"]):
        return "CLOUD"
    if any(x in combined for x in ["security_group", "ssh", "rdp", "ingress", "unrestricted", "cwe-668"]):
        return "NET"
    return "OTHER"


# ─────────────────────────────────────────────────────────────────────────────
# Roadmap step
# ─────────────────────────────────────────────────────────────────────────────

class RoadmapStep:
    def __init__(self, step_num: int, group_key: str, findings: List[Dict],
                 vuln_class: str, depends_on: List[str], reason: str):
        self.step_num    = step_num
        self.group_key   = group_key
        self.findings    = findings
        self.vuln_class  = vuln_class
        self.depends_on  = depends_on   # group_keys this must come after
        self.reason      = reason       # why this step is here

    def to_dict(self) -> Dict[str, Any]:
        f0          = self.findings[0]
        severity    = f0.get("severity", "UNKNOWN")
        title       = f0.get("title", "Unknown")
        fix_hint    = f0.get("fix_hint", "")
        fixed_code  = f0.get("fixed_code")
        effort_time, effort_desc = _effort(
            f0.get("rule_id", ""), f0.get("title", "")
        )

        # Collect unique files affected
        files = list(dict.fromkeys(
            f.get("file") for f in self.findings if f.get("file")
        ))

        return {
            "step":         self.step_num,
            "severity":     severity,
            "vuln_class":   self.vuln_class,
            "title":        title,
            "why_now":      self.reason,
            "depends_on":   self.depends_on,
            "occurrences":  len(self.findings),
            "files":        files,
            "fix_hint":     fix_hint,
            "fixed_code":   fixed_code,
            "effort":       effort_time,
            "effort_desc":  effort_desc,
            "finding_ids":  [f.get("id") for f in self.findings],
        }


# ─────────────────────────────────────────────────────────────────────────────
# Core roadmap builder
# ─────────────────────────────────────────────────────────────────────────────

def build_roadmap(scan: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build a dependency-aware remediation roadmap from a scan result.
    Returns a structured dict with ordered steps and metadata.
    """
    findings = scan.get("findings", [])
    if not findings:
        return {"steps": [], "summary": "No findings to remediate.", "total_steps": 0}

    # ── Step 1: Group findings by rule_id (same rule = same fix) ──
    groups: Dict[str, List[Dict]] = defaultdict(list)
    for f in findings:
        key = f.get("rule_id") or f.get("title", "unknown")
        groups[key].append(f)

    # ── Step 2: Classify each group ──
    group_class: Dict[str, str] = {}
    for key, flist in groups.items():
        group_class[key] = _vuln_class(flist[0])

    # ── Step 3: Build dependency graph between groups ──
    # class_to_groups maps vuln class → list of group keys with that class
    class_to_groups: Dict[str, List[str]] = defaultdict(list)
    for key, cls in group_class.items():
        class_to_groups[cls].append(key)

    # edges[dependent_key] = list of prerequisite_keys
    edges: Dict[str, List[str]] = defaultdict(list)
    dep_reasons: Dict[str, str] = {}  # dependent_key → reason string

    for prereq_class, dep_class, reason in DEPENDENCY_RULES:
        prereq_groups = class_to_groups.get(prereq_class, [])
        dep_groups    = class_to_groups.get(dep_class, [])
        for dep_key in dep_groups:
            for prereq_key in prereq_groups:
                if dep_key != prereq_key:
                    edges[dep_key].append(prereq_key)
                    dep_reasons[dep_key] = reason

    # ── Step 4: Topological sort with severity as tiebreaker ──
    # Kahn's algorithm
    in_degree: Dict[str, int] = {k: 0 for k in groups}
    for dep_key, prereqs in edges.items():
        for p in prereqs:
            if p in in_degree:
                in_degree[dep_key] = in_degree.get(dep_key, 0) + 1

    # Priority queue: (severity_weight, group_key)
    def _sev_weight(key: str) -> int:
        flist = groups[key]
        min_sev = min(SEV_WEIGHT.get(f.get("severity", "INFO"), 4) for f in flist)
        return min_sev

    ready = deque(sorted(
        [k for k, d in in_degree.items() if d == 0],
        key=_sev_weight
    ))

    ordered: List[str] = []
    while ready:
        key = ready.popleft()
        ordered.append(key)
        # Find all groups that depend on this key
        for dep_key, prereqs in edges.items():
            if key in prereqs:
                in_degree[dep_key] -= 1
                if in_degree[dep_key] == 0:
                    # Insert in severity order
                    inserted = False
                    for i, rk in enumerate(ready):
                        if _sev_weight(dep_key) < _sev_weight(rk):
                            ready.insert(i, dep_key)
                            inserted = True
                            break
                    if not inserted:
                        ready.append(dep_key)

    # Handle any cycles (shouldn't happen but be safe)
    remaining = [k for k in groups if k not in ordered]
    remaining.sort(key=_sev_weight)
    ordered.extend(remaining)

    # ── Step 5: Build steps ──
    steps = []
    for i, key in enumerate(ordered, start=1):
        flist      = groups[key]
        cls        = group_class[key]
        prereqs    = edges.get(key, [])
        reason     = dep_reasons.get(key, _default_reason(cls, i, flist))

        step = RoadmapStep(
            step_num   = i,
            group_key  = key,
            findings   = flist,
            vuln_class = cls,
            depends_on = prereqs,
            reason     = reason,
        )
        steps.append(step.to_dict())

    # ── Step 6: Summary ──
    total_critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    total_high     = sum(1 for f in findings if f.get("severity") == "HIGH")
    unique_types   = len(groups)

    effort_steps   = [s for s in steps if s["severity"] in ("CRITICAL", "HIGH")]
    quick_wins     = [s for s in steps if s["effort"].startswith("5") or s["effort"].startswith("10")]

    return {
        "scan_id":       scan.get("scan_id", ""),
        "repo":          scan.get("repo", ""),
        "total_steps":   len(steps),
        "unique_types":  unique_types,
        "total_findings":len(findings),
        "critical_steps":len([s for s in steps if s["severity"] == "CRITICAL"]),
        "quick_wins":    len(quick_wins),
        "estimated_total_effort": _total_effort(steps),
        "steps":         steps,
        "summary": (
            f"{len(steps)} fix steps identified for {len(findings)} findings across "
            f"{unique_types} vulnerability types. "
            f"{total_critical} critical and {total_high} high severity issues present. "
            f"Fix steps are ordered by dependency and severity — completing them in sequence "
            f"minimises the risk of introducing regressions."
        ),
    }


def _default_reason(cls: str, step_num: int, findings: List[Dict]) -> str:
    sev = findings[0].get("severity", "UNKNOWN") if findings else "UNKNOWN"
    reasons = {
        "INFO_DISCLOSURE": "Fix first — information disclosure gives attackers reconnaissance data that enables all other attacks",
        "CRED":            "Fix early — hardcoded credentials can be used immediately with no further exploitation required",
        "DB":              "High priority — SQL injection gives direct database access and can chain to RCE",
        "RCE":             "Critical — arbitrary code execution gives full server control",
        "PATH":            "Fix early — path traversal enables reading of config files and credentials",
        "XSS":             "Fix after server-side issues — XSS enables session hijacking and data theft in browsers",
        "CORS":            "Fix to limit cross-origin attack surface before addressing XSS",
        "NET":             "Fix network exposure to reduce attack surface before addressing application issues",
        "PRIVESC":         "Fix IAM over-privilege to contain blast radius of any successful attack",
        "CLOUD":           "Fix infrastructure misconfigurations — publicly exposed services are trivially reachable",
        "OTHER":           f"{sev} severity — fix as part of general security hardening",
    }
    return reasons.get(cls, f"{sev} severity finding requiring remediation")


def _total_effort(steps: List[Dict]) -> str:
    """Estimate total effort range across all steps."""
    total_min = 0
    total_max = 0
    for s in steps:
        effort = s.get("effort", "30 min")
        # Parse "X–Y min" or "X min"
        import re
        nums = re.findall(r"\d+", effort)
        if len(nums) >= 2:
            total_min += int(nums[0])
            total_max += int(nums[1])
        elif len(nums) == 1:
            total_min += int(nums[0])
            total_max += int(nums[0])

    if total_min == 0:
        return "Unknown"
    if total_min >= 60:
        h_min = total_min // 60
        h_max = total_max // 60
        m_min = total_min % 60
        m_max = total_max % 60
        if h_min == h_max:
            return f"~{h_min}h {m_min}–{m_max}min"
        return f"~{h_min}–{h_max}h"
    return f"~{total_min}–{total_max} min"
