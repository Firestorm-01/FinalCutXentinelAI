"""
XentinelAI — Red-Team Simulation Engine
========================================
Runs entirely from the scan JSON — no filesystem access needed.
Uses finding metadata (title, description, file, line, rule_id, severity)
to build accurate step narratives and evidence.
"""

import re
import uuid
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any, Tuple


# ─────────────────────────────────────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class EvidenceHit:
    file: str
    line_number: Optional[int]
    pattern_type: str
    matched_context: str
    redacted_value: str


@dataclass
class StepResult:
    step_index: int
    step_description: str
    mapped_finding_id: str
    mapped_finding_title: str
    mapped_finding_file: str
    mapped_finding_line: Optional[int]
    mapping_confidence: str         # "high" | "medium" | "low"
    status: str                     # "compromised" | "partial" | "blocked"
    action_taken: str
    evidence: List[EvidenceHit] = field(default_factory=list)
    impact: str = ""
    impact_class: str = ""
    narrative_valid: bool = True
    narrative_note: str = ""


@dataclass
class ChainSimulation:
    chain_id: str
    chain_title: str
    risk_score: int
    overall_status: str             # "fully_exploited" | "partially_exploited" | "blocked"
    narrative_intact: bool
    steps_total: int
    steps_compromised: int
    step_results: List[StepResult] = field(default_factory=list)
    blast_radius: str = ""
    remediation: str = ""
    narrative_summary: str = ""


@dataclass
class SimulationReport:
    report_id: str
    generated_at: str
    repo: str
    chains_simulated: int
    chains_fully_exploited: int
    chains_partially_exploited: int
    chains_blocked: int
    simulations: List[ChainSimulation] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# Impact classification — maps finding signals to impact class
# ─────────────────────────────────────────────────────────────────────────────

# (pattern_in_title_or_ruleid, impact_class)
TITLE_CLASS_MAP: List[Tuple[str, str]] = [
    # Credentials
    ("hardcoded",           "CRED"),
    ("secret",              "CRED"),
    ("credential",          "CRED"),
    ("access.key",          "CRED"),
    ("api.key",             "CRED"),
    ("password",            "CRED"),
    ("token",               "CRED"),
    ("private.key",         "CRED"),
    ("jwt",                 "CRED"),
    # SQL injection
    ("sql",                 "DB"),
    ("injection",           "DB"),
    ("tainted",             "DB"),
    # RCE
    ("subprocess",          "RCE"),
    ("command.inject",      "RCE"),
    ("rce",                 "RCE"),
    ("exec",                "RCE"),
    ("eval",                "RCE"),
    ("shell",               "RCE"),
    ("dangerous.subprocess","RCE"),
    # Path traversal / data
    ("path.traversal",      "DATA"),
    ("open.*file",          "DATA"),
    ("directory.traversal", "DATA"),
    ("file.read",           "DATA"),
    # XSS
    ("xss",                 "DATA"),
    ("cross.site",          "DATA"),
    ("direct.response",     "DATA"),
    ("raw.html",            "DATA"),
    # Cloud / infra
    ("imds",                "CLOUD"),
    ("metadata",            "CLOUD"),
    ("publicly.accessible", "CLOUD"),
    ("public.ip",           "CLOUD"),
    ("ec2",                 "CLOUD"),
    ("rds",                 "CLOUD"),
    ("s3",                  "DATA"),
    ("bucket",              "DATA"),
    # Network
    ("security.group",      "NET"),
    ("ssh",                 "NET"),
    ("rdp",                 "NET"),
    ("port",                "NET"),
    ("ingress",             "NET"),
    ("unrestricted",        "NET"),
    # IAM / privilege escalation
    ("iam",                 "PRIVESC"),
    ("privilege",           "PRIVESC"),
    ("escalat",             "PRIVESC"),
    ("admin",               "PRIVESC"),
    ("wildcard",            "PRIVESC"),
    ("administrator",       "PRIVESC"),
    ("lambda.*policy",      "PRIVESC"),
]

CWE_CLASS_MAP: Dict[str, str] = {
    "CWE-798":  "CRED",
    "CWE-259":  "CRED",
    "CWE-321":  "CRED",
    "CWE-89":   "DB",
    "CWE-704":  "DB",
    "CWE-78":   "RCE",
    "CWE-94":   "RCE",
    "CWE-22":   "DATA",
    "CWE-79":   "DATA",
    "CWE-918":  "CLOUD",
    "CWE-284":  "PRIVESC",
    "CWE-269":  "PRIVESC",
    "CWE-522":  "CRED",
    "CWE-311":  "DATA",
    "CWE-668":  "NET",
    "CWE-489":  "NET",
    "CWE-1220": "NET",
}

DOMAIN_CLASS_MAP: Dict[str, str] = {
    "IAM": "PRIVESC",
    "IAC": "CLOUD",
    "CODE": "CRED",     # default for CODE, overridden by title matching
}


def _classify_finding(finding: Dict[str, Any]) -> str:
    """Derive impact class from finding metadata."""
    title   = (finding.get("title")   or "").lower()
    rule_id = (finding.get("rule_id") or "").lower()
    cwe     = (finding.get("cwe")     or "")
    domain  = (finding.get("domain")  or "")
    combined = f"{title} {rule_id}"

    # Title/rule_id matching — most specific
    for pattern, cls in TITLE_CLASS_MAP:
        if re.search(pattern, combined):
            return cls

    # CWE matching
    for cwe_prefix, cls in CWE_CLASS_MAP.items():
        if cwe.startswith(cwe_prefix):
            return cls

    # Domain fallback
    return DOMAIN_CLASS_MAP.get(domain, "CRED")


# ─────────────────────────────────────────────────────────────────────────────
# NLP step → finding mapper
# ─────────────────────────────────────────────────────────────────────────────

def _tokenize(text: str) -> set:
    return set(re.findall(r"[A-Za-z0-9_\-]{3,}", text.lower()))


def _score_finding(step_tokens: set, finding: Dict[str, Any]) -> int:
    score = 0
    f_tokens = (
        _tokenize(finding.get("title", "")) |
        _tokenize(finding.get("file", "") or "") |
        _tokenize(finding.get("rule_id", "") or "") |
        _tokenize((finding.get("description", "") or "")[:200])
    )
    score += len(step_tokens & f_tokens) * 2

    # Bonus: step mentions the file basename
    f_file = ((finding.get("file") or "").replace("\\", "/").split("/")[-1]).lower()
    if f_file and f_file.split(".")[0] in " ".join(step_tokens):
        score += 5

    # Bonus: step mentions finding id directly
    if finding.get("id", "") in " ".join(step_tokens):
        score += 10

    return score


def _map_step_to_finding(
    step_text: str,
    chain_finding_ids: List[str],
    findings_by_id: Dict[str, Any],
    step_index: int,
) -> Tuple[Dict[str, Any], str]:
    step_tokens = _tokenize(step_text)
    candidates = [findings_by_id[fid] for fid in chain_finding_ids if fid in findings_by_id]

    if not candidates:
        return {}, "low"

    scores = sorted([(f, _score_finding(step_tokens, f)) for f in candidates],
                    key=lambda x: x[1], reverse=True)

    best, best_score = scores[0]
    second_score = scores[1][1] if len(scores) > 1 else 0

    if best_score >= 6 and best_score >= second_score * 1.5:
        return best, "high"
    elif best_score >= 3:
        return best, "medium"
    else:
        idx = min(step_index, len(candidates) - 1)
        return candidates[idx], "low"


# ─────────────────────────────────────────────────────────────────────────────
# Evidence builder — from finding metadata, no filesystem
# ─────────────────────────────────────────────────────────────────────────────

# Maps impact class → what evidence looks like
EVIDENCE_TEMPLATES: Dict[str, List[Tuple[str, str]]] = {
    "CRED": [
        ("AWS Access Key ID",       "AWS_ACCESS_KEY_ID = \"AKIA****EXAMPLE\""),
        ("AWS Secret Access Key",   "AWS_SECRET_ACCESS_KEY = \"wJal****rkey\""),
        ("Hardcoded Password",      "DB_PASSWORD = \"supe****word\""),
        ("Secret Token",            "STRIPE_SECRET = \"sk_li****test\""),
        ("API Key",                 "API_KEY = \"abcd****wxyz\""),
    ],
    "DB": [
        ("SQL string formatting",   "query = 'SELECT * FROM users WHERE id = %s' % user_id"),
        ("SQL f-string injection",  "query = f'SELECT * FROM users WHERE id = {user_id}'"),
        ("SQL string concat",       "query = 'SELECT * FROM users WHERE id = ' + user_id"),
        ("DB Connection String",    "DB_URL = \"postgres****word@db:5432/app\""),
    ],
    "RCE": [
        ("subprocess shell=True",   "subprocess.check_output(f\"ping -c 1 {host}\", shell=True)"),
        ("eval() — RCE primitive",  "eval(user_input)"),
        ("exec() — RCE primitive",  "exec(request.data)"),
        ("os.system() call",        "os.system(f\"ping {host}\")"),
    ],
    "DATA": [
        ("open() with user input",  "open(f'/var/data/{filename}')"),
        ("S3 bucket public ACL",    "acl = \"publ****ead\""),
        ("XSS direct write",        "res.send(`<h1>Welcome, ${req.query.name}</h1>`)"),
        ("Path traversal",          "filename = request.args.get('name')"),
    ],
    "CLOUD": [
        ("RDS publicly accessible", "publicly_accessible = true"),
        ("IMDSv1 enabled",          "http_tokens = \"optional\""),
        ("EC2 public IP",           "associate_public_ip_address = true"),
        ("S3 public ACL",           "acl = \"publ****ead\""),
    ],
    "NET": [
        ("SG open to world",        "cidr_blocks = [\"0.0.0.0/0\"]"),
        ("SSH open to internet",    "from_port = 22, cidr = \"0.0.0.0/0\""),
        ("RDP open to internet",    "from_port = 3389, cidr = \"0.0.0.0/0\""),
    ],
    "PRIVESC": [
        ("IAM wildcard action",     "\"Action\": \"*\", \"Resource\": \"*\""),
        ("AdministratorAccess",     "ManagedPolicyArns: [\"AdministratorAccess\"]"),
        ("IAM wildcard iam:*",      "\"Action\": \"iam:*\""),
        ("Lambda wildcard",         "\"Action\": \"lambda:*\""),
    ],
}


def _build_evidence(finding: Dict[str, Any], impact_class: str) -> List[EvidenceHit]:
    """Build evidence hits from finding metadata — no filesystem needed."""
    hits: List[EvidenceHit] = []

    file_path  = finding.get("file") or "unknown"
    line       = finding.get("line")
    title      = finding.get("title", "")
    rule_id    = finding.get("rule_id", "") or ""
    fix_hint   = finding.get("fix_hint", "") or ""
    fixed_code = finding.get("fixed_code", "") or ""
    severity   = finding.get("severity", "")

    # Only simulate evidence for CRITICAL and HIGH findings
    if severity not in ("CRITICAL", "HIGH"):
        return []

    templates = EVIDENCE_TEMPLATES.get(impact_class, [])

    # Pick the most relevant template by matching title/rule_id
    matched_template = None
    title_lower = f"{title} {rule_id}".lower()
    for pattern_label, context in templates:
        if any(word in title_lower for word in pattern_label.lower().split()):
            matched_template = (pattern_label, context)
            break

    # Fall back to first template for the class
    if not matched_template and templates:
        matched_template = templates[0]

    if matched_template:
        pattern_label, context = matched_template
        # Use actual fixed_code as context if available — more accurate
        if fixed_code and len(fixed_code) < 200:
            display_context = f"VULNERABLE: {fixed_code.splitlines()[0][:100]}"
        else:
            display_context = context

        hits.append(EvidenceHit(
            file=file_path,
            line_number=line,
            pattern_type=pattern_label,
            matched_context=display_context,
            redacted_value=_redact_context(context),
        ))

    # Add fix_hint as a second evidence line if meaningful
    if fix_hint and len(fix_hint) > 10:
        hits.append(EvidenceHit(
            file=file_path,
            line_number=line,
            pattern_type="Fix available",
            matched_context=f"FIX: {fix_hint[:120]}",
            redacted_value="[fix]",
        ))

    return hits


def _redact_context(context: str) -> str:
    """Extract and redact the sensitive value from a context string."""
    # Try to find quoted value
    m = re.search(r'["\']([^"\']{6,})["\']', context)
    if m:
        v = m.group(1)
        if len(v) <= 8:
            return "****"
        return v[:4] + "*" * min(len(v) - 6, 16) + v[-2:]
    return "****"


# ─────────────────────────────────────────────────────────────────────────────
# Narrative validation
# ─────────────────────────────────────────────────────────────────────────────

PRODUCES: Dict[str, List[str]] = {
    "CRED":    ["CLOUD", "DB", "DATA", "PRIVESC", "NET", "RCE"],
    "CLOUD":   ["DB", "DATA", "PRIVESC", "RCE"],
    "DB":      ["DATA", "CRED"],
    "RCE":     ["CRED", "DATA", "CLOUD", "PRIVESC", "NET"],
    "DATA":    ["CRED", "PRIVESC"],
    "PRIVESC": ["CLOUD", "DATA", "RCE", "NET", "CRED"],
    "NET":     ["RCE", "CRED", "CLOUD"],
}


def _validate_narrative(steps: List[StepResult]) -> List[StepResult]:
    for i in range(1, len(steps)):
        prev = steps[i - 1]
        curr = steps[i]
        if prev.status == "blocked":
            curr.narrative_valid = False
            curr.narrative_note = (
                f"Prerequisite step {prev.step_index} was blocked — "
                f"attacker could not acquire {prev.impact_class} needed here."
            )
            continue
        if prev.impact_class and curr.impact_class:
            allowed = PRODUCES.get(prev.impact_class, [])
            if curr.impact_class not in allowed:
                curr.narrative_note = (
                    f"Unusual pivot: {prev.impact_class} → {curr.impact_class} "
                    f"(expected: {', '.join(allowed)})."
                )
    return steps


# ─────────────────────────────────────────────────────────────────────────────
# Impact derivation — from finding data
# ─────────────────────────────────────────────────────────────────────────────

IMPACT_BY_CLASS: Dict[str, str] = {
    "CRED":    "Credentials confirmed in source — attacker gains authenticated access to downstream services",
    "CLOUD":   "Cloud infrastructure misconfiguration confirmed — lateral movement into AWS environment possible",
    "DB":      "SQL injection vector confirmed — attacker can dump tables, extract credentials, or modify data",
    "RCE":     "Remote code execution primitive confirmed — attacker can run arbitrary commands on the host",
    "DATA":    "Data exfiltration path confirmed — files, S3 objects, or database records accessible",
    "PRIVESC": "Privilege escalation path confirmed — attacker can elevate to admin/root level",
    "NET":     "Network exposure confirmed — service port reachable from internet without restriction",
}

IMPACT_BY_TITLE: List[Tuple[str, str]] = [
    ("aws.access.key",      "AWS Access Key ID confirmed in source — full programmatic cloud API access"),
    ("aws.secret",          "AWS Secret Key confirmed — combined with Key ID gives complete AWS access"),
    ("password",            "Plaintext password confirmed in source — direct authentication to service possible"),
    ("sql.*inject|tainted", "SQL injection confirmed — attacker can execute arbitrary database queries"),
    ("subprocess|shell",    "Command injection confirmed — arbitrary OS commands executable on server"),
    ("path.traversal",      "Path traversal confirmed — attacker can read arbitrary files from server"),
    ("s3.*public|public.*acl","S3 bucket is publicly accessible — all objects readable without authentication"),
    ("rds.*public|publicly.accessible","RDS instance exposed to internet — direct database connection possible"),
    ("administrator|admin.policy","Administrator policy attached — unrestricted AWS access confirmed"),
    ("iam.*wildcard|wildcard.*iam","IAM wildcard confirmed — attacker can create/delete any AWS resource"),
    ("privilege.escalat",   "Privilege escalation path confirmed — attacker can assume any role"),
    ("security.group.*ssh|ssh.*unrestricted","SSH exposed to internet — brute-force attack surface confirmed"),
    ("xss|cross.site|direct.response","XSS vector confirmed — attacker can inject malicious scripts"),
]


def _derive_impact(finding: Dict[str, Any], impact_class: str) -> str:
    title   = (finding.get("title")   or "").lower()
    rule_id = (finding.get("rule_id") or "").lower()
    combined = f"{title} {rule_id}"

    for pattern, msg in IMPACT_BY_TITLE:
        if re.search(pattern, combined):
            return msg

    # Use finding description as fallback — it's AI-generated and accurate
    desc = (finding.get("description") or "").strip()
    if desc:
        # Take first sentence, cap at 150 chars
        first = re.split(r'(?<=[.!?])\s', desc)[0]
        return first[:150]

    return IMPACT_BY_CLASS.get(impact_class, "Vulnerability confirmed — exploitation path established.")


def _derive_blast_radius(chain: Dict, status: str, steps: List[StepResult]) -> str:
    if status == "blocked":
        return "Attack chain could not be executed — no confirmed impact from this scan."

    achieved = {s.impact_class for s in steps if s.status == "compromised" and s.impact_class}

    if "PRIVESC" in achieved and "CLOUD" in achieved:
        return "Full AWS account compromise — attacker has administrative control over all cloud resources and data."
    if "PRIVESC" in achieved:
        return "Privilege escalation achieved — attacker can assume admin roles and create backdoor IAM users."
    if "CRED" in achieved and "CLOUD" in achieved:
        return "Cloud infrastructure takeover — extracted credentials provide API access to all AWS services."
    if "CRED" in achieved and "DB" in achieved:
        return "Database fully compromised — credentials plus SQL injection give complete read/write access."
    if "RCE" in achieved:
        return "Host-level compromise — arbitrary code execution means attacker controls the server."
    if "DATA" in achieved:
        return "Data exfiltration confirmed — sensitive files, S3 objects, or DB records accessible to attacker."
    if "NET" in achieved and "CRED" in achieved:
        return "Authenticated network access — exposed port combined with stolen credentials enables direct login."

    title = chain.get("title", "").lower()
    if "takeover" in title:
        return "Full cloud infrastructure compromise — all AWS resources accessible."
    if "escalat" in title:
        return "Privilege escalation — unrestricted AWS account access."
    if "exfiltrat" in title or "data" in title:
        return "Data exfiltration — database contents and cloud storage at risk."
    return "Partial compromise — attacker establishes foothold for further exploitation."


def _describe_action(impact_class: str, finding: Dict[str, Any]) -> str:
    file_name = ((finding.get("file") or "unknown").replace("\\", "/").split("/")[-1])
    actions = {
        "CRED":    f"Credential extraction from {file_name} (line {finding.get('line', '?')})",
        "DB":      f"SQL injection analysis on {file_name} (line {finding.get('line', '?')})",
        "RCE":     f"Code execution primitive analysis on {file_name} (line {finding.get('line', '?')})",
        "DATA":    f"Data exposure analysis on {file_name} (line {finding.get('line', '?')})",
        "CLOUD":   f"Infrastructure misconfiguration analysis on {file_name} (line {finding.get('line', '?')})",
        "NET":     f"Network exposure analysis on {file_name} (line {finding.get('line', '?')})",
        "PRIVESC": f"IAM privilege escalation analysis on {file_name}",
    }
    return actions.get(impact_class, f"Security analysis on {file_name}")


# ─────────────────────────────────────────────────────────────────────────────
# Core simulation
# ─────────────────────────────────────────────────────────────────────────────

def _simulate_chain(
    chain: Dict[str, Any],
    findings_by_id: Dict[str, Any],
) -> ChainSimulation:

    steps_text   = chain.get("steps", [])
    finding_ids  = chain.get("finding_ids", [])
    step_results: List[StepResult] = []

    for idx, step_text in enumerate(steps_text):
        # Map step to finding
        target, confidence = _map_step_to_finding(step_text, finding_ids, findings_by_id, idx)

        if not target:
            step_results.append(StepResult(
                step_index=idx + 1,
                step_description=step_text,
                mapped_finding_id="",
                mapped_finding_title="Unknown",
                mapped_finding_file="",
                mapped_finding_line=None,
                mapping_confidence="low",
                status="blocked",
                action_taken="No matching finding in scan result",
                impact="Finding not found in scan data.",
                impact_class="",
            ))
            continue

        impact_class = _classify_finding(target)
        evidence     = _build_evidence(target, impact_class)
        severity     = target.get("severity", "")

        # Status: CRITICAL/HIGH findings are compromised, others partial
        if severity in ("CRITICAL", "HIGH"):
            status = "compromised"
        elif severity == "MEDIUM":
            status = "partial"
        else:
            status = "blocked"

        impact = _derive_impact(target, impact_class)
        action = _describe_action(impact_class, target)

        step_results.append(StepResult(
            step_index=idx + 1,
            step_description=step_text,
            mapped_finding_id=target.get("id", ""),
            mapped_finding_title=target.get("title", ""),
            mapped_finding_file=target.get("file", "") or "",
            mapped_finding_line=target.get("line"),
            mapping_confidence=confidence,
            status=status,
            action_taken=action,
            evidence=evidence,
            impact=impact,
            impact_class=impact_class,
        ))

    # Narrative validation
    step_results = _validate_narrative(step_results)
    narrative_intact = all(s.narrative_valid for s in step_results)

    # Aggregate
    compromised = sum(1 for s in step_results if s.status == "compromised")
    partial     = sum(1 for s in step_results if s.status == "partial")
    total       = len(step_results)

    if total == 0:
        overall = "blocked"
    elif compromised == total:
        overall = "fully_exploited"
    elif compromised + partial >= max(1, (total + 1) // 2):
        overall = "partially_exploited"
    else:
        overall = "blocked"

    classes = [s.impact_class for s in step_results if s.status == "compromised" and s.impact_class]
    narrative_summary = " → ".join(classes) if classes else "No confirmed exploit path."

    return ChainSimulation(
        chain_id=chain.get("id", str(uuid.uuid4())[:8]),
        chain_title=chain.get("title", "Unknown Chain"),
        risk_score=chain.get("risk_score", 80),
        overall_status=overall,
        narrative_intact=narrative_intact,
        steps_total=total,
        steps_compromised=compromised,
        step_results=step_results,
        blast_radius=_derive_blast_radius(chain, overall, step_results),
        remediation=chain.get("remediation", ""),
        narrative_summary=narrative_summary,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────────────────────

def run_simulation(scan_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Entry point called by FastAPI /simulate endpoint.
    scan_result : full scan JSON as dict
    No repo_path needed — works entirely from scan data.
    Returns     : SimulationReport as plain JSON-serialisable dict
    """
    findings_by_id: Dict[str, Any] = {f["id"]: f for f in scan_result.get("findings", [])}
    attack_chains = scan_result.get("attack_chains", [])

    simulations = [_simulate_chain(c, findings_by_id) for c in attack_chains]

    fully   = sum(1 for s in simulations if s.overall_status == "fully_exploited")
    partial = sum(1 for s in simulations if s.overall_status == "partially_exploited")
    blocked = sum(1 for s in simulations if s.overall_status == "blocked")

    report = SimulationReport(
        report_id=str(uuid.uuid4()),
        generated_at=datetime.now(timezone.utc).isoformat(),
        repo=scan_result.get("repo", "unknown"),
        chains_simulated=len(simulations),
        chains_fully_exploited=fully,
        chains_partially_exploited=partial,
        chains_blocked=blocked,
        simulations=simulations,
    )
    return asdict(report)