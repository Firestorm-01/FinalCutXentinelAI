import json
import os
import re
import glob
from typing import List, Dict, Any, Set
from models import Finding, Severity, Domain

DANGEROUS_ACTIONS: Dict[str, tuple] = {
    "*":                             (Severity.CRITICAL.value, "Wildcard action grants ALL AWS permissions"),
    "iam:*":                         (Severity.CRITICAL.value, "Full IAM control — can escalate to any privilege"),
    "iam:createpolicy":              (Severity.HIGH.value,     "Can create arbitrary IAM policies"),
    "iam:attachrolepolicy":          (Severity.HIGH.value,     "Can attach any policy to any role"),
    "iam:attachuserpolicy":          (Severity.HIGH.value,     "Can attach any policy to any user"),
    "iam:putrolepolicy":             (Severity.HIGH.value,     "Can inject inline policies into roles"),
    "iam:createaccesskey":           (Severity.HIGH.value,     "Can create long-lived access keys for any user"),
    "iam:passrole":                  (Severity.HIGH.value,     "Can pass roles to services — classic escalation vector"),
    "iam:createpolicyversion":       (Severity.CRITICAL.value, "Can update a policy to grant admin — privilege escalation"),
    "iam:setdefaultpolicyversion":   (Severity.HIGH.value,     "Can revert policy to a broader version"),
    "iam:createloginprofile":        (Severity.HIGH.value,     "Can create console login for any IAM user"),
    "iam:updateloginprofile":        (Severity.HIGH.value,     "Can reset password of any IAM user including admins"),
    "sts:assumerole":                (Severity.MEDIUM.value,   "Can assume roles — verify trust policy scope"),
    "s3:*":                          (Severity.HIGH.value,     "Full S3 access on all buckets"),
    "ec2:*":                         (Severity.HIGH.value,     "Full EC2 control"),
    "lambda:*":                      (Severity.HIGH.value,     "Full Lambda control — can execute arbitrary code"),
    "cloudformation:*":              (Severity.HIGH.value,     "Full CloudFormation — can deploy any resource"),
    "secretsmanager:getsecretvalue": (Severity.MEDIUM.value,  "Can read all secrets from Secrets Manager"),
    "kms:decrypt":                   (Severity.MEDIUM.value,  "Can decrypt KMS-protected data"),
}

ESCALATION_COMBOS: List[Dict] = [
    {
        "actions":     {"iam:attachrolepolicy", "iam:passrole"},
        "description": "Can attach policies to roles and pass them — full privilege escalation path",
        "severity":    Severity.CRITICAL.value,
    },
    {
        "actions":     {"lambda:createfunction", "iam:passrole"},
        "description": "Can create Lambda with admin role — arbitrary code execution as admin",
        "severity":    Severity.CRITICAL.value,
    },
    {
        "actions":     {"cloudformation:createstack", "iam:passrole"},
        "description": "Can deploy CloudFormation stack with admin role — full infrastructure takeover",
        "severity":    Severity.CRITICAL.value,
    },
    {
        "actions":     {"ec2:runinstances", "iam:passrole"},
        "description": "Can launch EC2 instance with admin instance profile",
        "severity":    Severity.HIGH.value,
    },
    {
        "actions":     {"iam:attachuserpolicy", "iam:createaccesskey"},
        "description": "Can attach admin policy to any user then create their access key",
        "severity":    Severity.CRITICAL.value,
    },
]

ADMIN_POLICY_ARNS = {
    "arn:aws:iam::aws:policy/administratoraccess",
    "arn:aws:iam::aws:policy/poweruseraccess",
    "arn:aws:iam::aws:policy/iamfullaccess",
}


def _extract_actions(statement: Dict) -> List[str]:
    actions = statement.get("Action", [])
    if isinstance(actions, str):
        actions = [actions]
    elif not isinstance(actions, list):
        actions = []
    return [str(a).lower() for a in actions]


def _is_allow(statement: Any) -> bool:
    if not isinstance(statement, dict):
        return False
    return statement.get("Effect", "").upper() == "ALLOW"


def _resource_is_wildcard(statement: Dict) -> bool:
    resource = statement.get("Resource", "")
    if isinstance(resource, list):
        return "*" in resource or any(str(r).endswith("*") and str(r) == "*" for r in resource)
    return str(resource).strip() == "*"


def analyze_policy_document(
    policy_doc: Any, policy_name: str, entity_name: str
) -> List[Finding]:
    if not isinstance(policy_doc, dict):
        return []

    findings: List[Finding] = []
    all_actions: Set[str]   = set()

    statements = policy_doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    elif not isinstance(statements, list):
        return []

    for stmt in statements:
        if not _is_allow(stmt):
            continue

        actions = _extract_actions(stmt)
        all_actions.update(actions)
        wildcard_resource = _resource_is_wildcard(stmt)

        for action in actions:
            matched = False
            for danger_key, (sev, desc) in DANGEROUS_ACTIONS.items():
                dk_lower = danger_key.lower()
                if action == dk_lower:
                    matched = True
                elif dk_lower.endswith(":*") and action.startswith(dk_lower[:-1]):
                    matched = True

                if matched:
                    effective_sev = sev if wildcard_resource else Severity.MEDIUM.value
                    findings.append(Finding(
                        domain      = Domain.IAM.value,
                        severity    = effective_sev,
                        title       = f"Dangerous IAM action: {danger_key}",
                        description = (
                            f"{entity_name} ({policy_name}): {desc}"
                            + (" — applied to ALL resources (*)." if wildcard_resource else ".")
                        ),
                        file        = policy_name,
                        rule_id     = f"IAM-{re.sub(r'[^a-zA-Z0-9]', '-', danger_key).upper()}",
                    ))
                    break

    # Check privilege escalation combos
    for combo in ESCALATION_COMBOS:
        if combo["actions"].issubset(all_actions):
            findings.append(Finding(
                domain      = Domain.IAM.value,
                severity    = combo["severity"],
                title       = "Privilege Escalation Path Detected",
                description = (
                    f"{entity_name} ({policy_name}): {combo['description']}. "
                    f"Triggering actions: {', '.join(sorted(combo['actions']))}"
                ),
                file        = policy_name,
                rule_id     = "IAM-PRIV-ESCALATION",
            ))

    return findings


def _scan_json_file(fpath: str, repo_path: str) -> List[Finding]:
    findings: List[Finding] = []
    rel_path = fpath[len(repo_path):].lstrip("/\\") if fpath.startswith(repo_path) else fpath

    try:
        with open(fpath, encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
    except (json.JSONDecodeError, PermissionError, OSError):
        return []

    if not isinstance(data, dict):
        return []

    # Raw IAM policy document
    if "Statement" in data:
        findings.extend(analyze_policy_document(data, rel_path, rel_path))

    # CloudFormation template
    resources = data.get("Resources", {})
    if not isinstance(resources, dict):
        return findings

    for res_name, res in resources.items():
        if not isinstance(res, dict):
            continue
        res_type = res.get("Type", "")
        props    = res.get("Properties", {}) or {}

        if res_type in ("AWS::IAM::Role", "AWS::IAM::User", "AWS::IAM::Group"):
            # Managed policy attachments
            managed = props.get("ManagedPolicyArns", []) or []
            for arn in managed:
                if str(arn).lower() in ADMIN_POLICY_ARNS:
                    findings.append(Finding(
                        domain      = Domain.IAM.value,
                        severity    = Severity.CRITICAL.value,
                        title       = f"Admin Managed Policy: {str(arn).split('/')[-1]}",
                        description = (
                            f"Resource '{res_name}' ({res_type}) has '{arn}' attached. "
                            "This grants unrestricted AWS access — violates least privilege."
                        ),
                        file        = rel_path,
                        rule_id     = "IAM-ADMIN-MANAGED-POLICY",
                    ))

            # Inline policies
            for inline in props.get("Policies", []) or []:
                if not isinstance(inline, dict):
                    continue
                doc = inline.get("PolicyDocument", {})
                if doc:
                    findings.extend(analyze_policy_document(doc, rel_path, res_name))

        # AWS::IAM::Policy or AWS::IAM::ManagedPolicy
        if res_type in ("AWS::IAM::Policy", "AWS::IAM::ManagedPolicy"):
            doc = props.get("PolicyDocument", {})
            if doc:
                findings.extend(analyze_policy_document(doc, rel_path, res_name))

    return findings


def _scan_tf_file(fpath: str, repo_path: str) -> List[Finding]:
    findings: List[Finding] = []
    rel_path = fpath[len(repo_path):].lstrip("/\\") if fpath.startswith(repo_path) else fpath

    try:
        with open(fpath, encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except (PermissionError, OSError):
        return []

    # Try to extract embedded JSON policy documents from jsonencode() blocks
    blocks = re.findall(
        r'policy\s*=\s*jsonencode\s*\(\s*(\{.*?\})\s*\)',
        content, re.DOTALL
    )
    for block in blocks:
        clean = re.sub(r'#[^\n]*', '', block)  # strip TF comments
        try:
            doc = json.loads(clean)
            findings.extend(analyze_policy_document(doc, rel_path, rel_path))
        except (json.JSONDecodeError, ValueError):
            pass

    # Also check heredoc policy strings
    heredocs = re.findall(r'<<[~-]?EOF\s*(.*?)\s*EOF', content, re.DOTALL | re.IGNORECASE)
    for block in heredocs:
        try:
            doc = json.loads(block.strip())
            findings.extend(analyze_policy_document(doc, rel_path, rel_path))
        except (json.JSONDecodeError, ValueError):
            pass

    # Quick scan for admin policy references
    lines = content.splitlines()
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("//"):
            continue
        for admin_key in ("AdministratorAccess", "PowerUserAccess", "IAMFullAccess"):
            if admin_key in line:
                findings.append(Finding(
                    domain      = Domain.IAM.value,
                    severity    = Severity.CRITICAL.value,
                    title       = f"Admin Policy Reference: {admin_key}",
                    description = (
                        f"'{admin_key}' referenced in {rel_path}:{i}. "
                        "This grants broad AWS access — scope to minimum required permissions."
                    ),
                    file        = rel_path,
                    line        = i,
                    rule_id     = "IAM-TF-ADMIN-POLICY",
                ))

    return findings


def run(repo_path: str) -> List[Finding]:
    """Scan all IAM policy files (JSON, CloudFormation, Terraform) in repo."""
    all_findings: List[Finding] = []

    # JSON files (raw policies + CloudFormation)
    for fpath in glob.glob(os.path.join(repo_path, "**/*.json"), recursive=True):
        all_findings.extend(_scan_json_file(fpath, repo_path))

    # YAML CloudFormation templates
    for fpath in glob.glob(os.path.join(repo_path, "**/*.yaml"), recursive=True):
        all_findings.extend(_scan_yaml_cfn(fpath, repo_path))
    for fpath in glob.glob(os.path.join(repo_path, "**/*.yml"), recursive=True):
        all_findings.extend(_scan_yaml_cfn(fpath, repo_path))

    # Terraform files
    for fpath in glob.glob(os.path.join(repo_path, "**/*.tf"), recursive=True):
        all_findings.extend(_scan_tf_file(fpath, repo_path))

    # Deduplicate by (rule_id, file, line)
    seen: Set[tuple] = set()
    unique: List[Finding] = []
    for f in all_findings:
        key = (f.rule_id, f.file, f.line)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return unique


def _scan_yaml_cfn(fpath: str, repo_path: str) -> List[Finding]:
    """Best-effort YAML CloudFormation scan using PyYAML if available."""
    findings: List[Finding] = []
    rel_path = fpath[len(repo_path):].lstrip("/\\") if fpath.startswith(repo_path) else fpath

    try:
        import yaml  # type: ignore
        with open(fpath, encoding="utf-8", errors="ignore") as f:
            data = yaml.safe_load(f)
    except Exception:
        return []

    if not isinstance(data, dict) or "Resources" not in data:
        return []

    resources = data.get("Resources", {}) or {}
    if not isinstance(resources, dict):
        return []

    for res_name, res in resources.items():
        if not isinstance(res, dict):
            continue
        res_type = res.get("Type", "")
        props    = res.get("Properties", {}) or {}

        if res_type in ("AWS::IAM::Role", "AWS::IAM::User", "AWS::IAM::Group",
                        "AWS::IAM::Policy", "AWS::IAM::ManagedPolicy"):
            managed = props.get("ManagedPolicyArns", []) or []
            for arn in managed:
                if str(arn).lower() in ADMIN_POLICY_ARNS:
                    findings.append(Finding(
                        domain      = Domain.IAM.value,
                        severity    = Severity.CRITICAL.value,
                        title       = f"Admin Managed Policy: {str(arn).split('/')[-1]}",
                        description = f"Resource '{res_name}' in {rel_path} has '{arn}' attached.",
                        file        = rel_path,
                        rule_id     = "IAM-ADMIN-MANAGED-POLICY",
                    ))
            doc = props.get("PolicyDocument", {})
            if doc:
                findings.extend(analyze_policy_document(doc, rel_path, res_name))

    return findings
