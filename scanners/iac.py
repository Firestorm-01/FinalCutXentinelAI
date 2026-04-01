import subprocess
import json
import os
import re
from typing import List
from models import Finding, Severity, Domain

CRITICAL_CHECKS = {
    "CKV_AWS_20", "CKV_AWS_53", "CKV_AWS_54",
    "CKV_AWS_23", "CKV_AWS_24",
    "CKV_AWS_17",
    "CKV_AWS_111",
}

PRIORITY_CHECKS = {
    "CKV_AWS_18":  "S3 access logging disabled",
    "CKV_AWS_19":  "S3 encryption not enabled",
    "CKV_AWS_20":  "S3 bucket allows public ACL",
    "CKV_AWS_21":  "S3 versioning disabled",
    "CKV_AWS_53":  "S3 Block Public Access not enabled",
    "CKV_AWS_54":  "S3 bucket allows public policy",
    "CKV_AWS_23":  "Security group allows unrestricted SSH (port 22)",
    "CKV_AWS_24":  "Security group allows unrestricted RDP (port 3389)",
    "CKV_AWS_25":  "Security group unrestricted ingress",
    "CKV_AWS_17":  "RDS instance publicly accessible",
    "CKV_AWS_16":  "RDS instance not encrypted",
    "CKV_AWS_7":   "CloudTrail not enabled",
    "CKV_AWS_36":  "CloudTrail log validation disabled",
    "CKV_AWS_3":   "EBS volume not encrypted",
    "CKV_AWS_8":   "EC2 instance has public IP",
    "CKV_AWS_79":  "EC2 IMDSv2 not enforced",
    "CKV_AWS_111": "IAM policy allows wildcard resource (*)",
    "CKV_AWS_40":  "IAM user has direct policy attachment",
    "CKV_AWS_58":  "EKS cluster encryption not enabled",
    "CKV_AWS_2":   "Lambda function not encrypted",
    "CKV_AWS_45":  "Lambda function environment variables not encrypted",
    "CKV_AWS_50":  "Lambda function X-Ray tracing disabled",
    "CKV_AWS_116": "Lambda function DLQ not configured",
    "CKV_AWS_272": "Lambda function code signing not enabled",
    # CloudFormation extras
    "CKV_AWS_55":  "S3 bucket public access not blocked",
    "CKV_AWS_56":  "S3 bucket public access policy not blocked",
    "CKV_AWS_107": "IAM policy with credentials exposure",
    "CKV_AWS_109": "IAM policy with privilege escalation actions",
    "CKV_AWS_110": "IAM policy allows privilege escalation",
    "CKV_AWS_144": "S3 cross-region replication not enabled",
}


def _clean_file_path(raw_path: str, repo_path: str) -> str:
    """
    Robustly strip server-side absolute paths from Checkov output.
    Checkov returns absolute paths like /uploads/uploaded_repo/myrepo/infra/main.tf
    but repo_path might be /home/uploads/myrepo — so simple startswith() fails.
    Strategy: find the repo basename in the raw path and return from there.
    """
    if not raw_path:
        return ""

    # Try exact prefix strip first
    if raw_path.startswith(repo_path):
        return raw_path[len(repo_path):].lstrip("/\\")

    # Find the repo basename in the absolute path and strip everything before it
    repo_name = os.path.basename(repo_path.rstrip("/\\"))
    if repo_name:
        # e.g. raw = /uploads/uploaded_repo/myrepo/infra/main.tf, repo_name = myrepo
        pattern = re.escape(repo_name) + r"[/\\]"
        match = re.search(pattern, raw_path)
        if match:
            return raw_path[match.start():]

    # Last resort: just return the filename portion
    return os.path.basename(raw_path)


def _human_title(check_id: str, check_name: str) -> str:
    """Return a human-readable title — never a raw CKV_AWS_XXX rule code."""
    # Known check → use our friendly name
    if check_id in PRIORITY_CHECKS:
        return PRIORITY_CHECKS[check_id]
    # Checkov provided a name
    if check_name and not check_name.startswith("CKV"):
        return check_name
    # Convert CKV_AWS_144 → "Aws 144 Security Check" as last resort
    parts = check_id.replace("_", " ").title().split()
    return " ".join(parts)


def _parse_checkov_output(raw: str) -> list:
    """Safely parse checkov JSON output — handles list, dict, or mixed."""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"[IAC SCANNER] JSON parse error: {e}")
        return []

    failed = []
    if isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue
            results = item.get("results", {})
            if isinstance(results, dict):
                failed.extend(results.get("failed_checks", []))
            elif isinstance(results, list):
                failed.extend(results)
    elif isinstance(data, dict):
        results = data.get("results", {})
        if isinstance(results, dict):
            failed.extend(results.get("failed_checks", []))
        elif isinstance(results, list):
            failed.extend(results)

    return failed


def run(repo_path: str) -> List[Finding]:
    findings: List[Finding] = []

    cmd = [
        "checkov",
        "--directory", repo_path,
        "--output", "json",
        "--quiet",
        "--compact",
        "--framework", "terraform,cloudformation,arm,kubernetes",
        "--download-external-modules", "false",
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        raw = result.stdout.strip()
        if not raw:
            return []
    except subprocess.TimeoutExpired:
        print("[IAC SCANNER] Checkov timed out")
        return []
    except FileNotFoundError:
        print("[IAC SCANNER] checkov not found — install: pip install checkov")
        return []

    failed_checks = _parse_checkov_output(raw)

    for check in failed_checks:
        if not isinstance(check, dict):
            continue

        check_id   = check.get("check_id", "")
        check_type = check.get("check_type", "terraform").upper()

        if check_id in CRITICAL_CHECKS:
            severity = Severity.CRITICAL.value
        elif check_id in PRIORITY_CHECKS:
            severity = Severity.HIGH.value
        else:
            severity = Severity.MEDIUM.value

        # Robustly clean the file path
        raw_path  = check.get("repo_file_path") or check.get("file_path") or ""
        file_path = _clean_file_path(raw_path, repo_path)

        # Line number
        line_range = check.get("file_line_range") or []
        line = line_range[0] if line_range else None

        # Human-readable title
        check_obj  = check.get("check", {}) or {}
        check_name = check_obj.get("name", "") if isinstance(check_obj, dict) else ""
        title      = _human_title(check_id, check_name)

        resource = check.get("resource", "unknown")

        findings.append(Finding(
            domain      = Domain.IAC.value,
            severity    = severity,
            title       = title,
            description = (
                f"{check_type} check {check_id} failed on resource '{resource}'. "
                f"{check_name}"
            ).strip(),
            file        = file_path or None,
            line        = line,
            rule_id     = check_id,
        ))

    return findings
