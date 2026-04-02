"""
XentinelAI — Secret Rotation Advisor
For each hardcoded secret finding, generates:
  - Secret type identification (regex-matched against the actual secret value)
  - Step-by-step rotation runbook for that specific service
  - Replacement code (env var + os.environ.get + secrets manager snippet)
  - Urgency rating based on severity

Endpoint: GET /scan/{scan_id}/secret-advisor
Pure analysis — no network calls, no external APIs.
"""

import re
from typing import Dict, Any, List, Optional, Tuple


# ─────────────────────────────────────────────────────────────────────────────
# Secret-type classifier: ordered list of (compiled_regex, secret_type)
# Each pattern is matched against the *actual secret value* extracted from the
# finding (finding["value"] or finding["match"]), falling back to the combined
# metadata string so older scan formats still work.
# ─────────────────────────────────────────────────────────────────────────────

_RAW_PATTERNS: List[Tuple[str, str]] = [
    # AWS
    (r"AKIA[0-9A-Z]{16}",                                              "aws_access_key"),
    (r"(?i)aws.{0,20}secret.{0,5}[=:\s]['\"]?[A-Za-z0-9/+=]{35,40}", "aws_secret_key"),
    # Stripe — match sk_live / sk_test prefixes directly
    (r"sk_live_[A-Za-z0-9]{24,}",                                      "stripe_live_key"),
    (r"sk_test_[A-Za-z0-9]{24,}",                                      "stripe_test_key"),
    # GitHub
    (r"ghp_[A-Za-z0-9]{36}",                                           "github_pat"),
    (r"gho_[A-Za-z0-9]{36}",                                           "github_oauth"),
    (r"github_pat_[A-Za-z0-9_]{82}",                                   "github_pat"),   # fine-grained PAT format
    # Slack
    (r"xox[baprs]-[0-9A-Za-z\-]{20,}",                                 "slack_token"),
    # JWT (three base64url segments separated by dots)
    (r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",        "jwt_token"),
    # Database connection strings
    (r"(?i)(mysql|postgresql|postgres|mongodb(\+srv)?|redis)://\S{8,}", "db_connection_string"),
    # Hardcoded passwords — require quotes so we don't catch variable names
    (r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{6,}['\"]",       "hardcoded_password"),
    # Generic API key — must be at least 16 chars, quoted or after = / :
    (r"(?i)(api[_\-]?key|apikey)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{16,}", "generic_api_key"),
    # Generic secret / token — require quotes to reduce false positives
    (r"(?i)(secret|token)\s*[=:]\s*['\"][A-Za-z0-9_\-\.]{16,}['\"]",  "generic_secret"),
]

# Pre-compile once at import time
SECRET_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(pattern), secret_type)
    for pattern, secret_type in _RAW_PATTERNS
]


# ─────────────────────────────────────────────────────────────────────────────
# Per-service rotation metadata
# ─────────────────────────────────────────────────────────────────────────────

SECRET_META: Dict[str, Dict[str, Any]] = {
    "aws_access_key": {
        "name":    "AWS Access Key ID",
        "service": "Amazon Web Services (IAM)",
        "risk":    "Full programmatic AWS API access — an attacker can enumerate, "
                   "create, and delete any AWS resource.",
        "rotation_steps": [
            "Sign in to AWS Console → IAM → Users → select the affected user.",
            "Go to the Security Credentials tab → Access Keys section.",
            "Click 'Create access key' to generate new credentials.",
            "Update all applications and CI/CD pipelines with the new key.",
            "Click 'Deactivate' on the old key and verify nothing breaks for ~24 h.",
            "Click 'Delete' on the old key after the grace period.",
            "Verify: aws sts get-caller-identity --profile new-key",
        ],
        "env_var":         "AWS_ACCESS_KEY_ID",
        "secrets_manager": (
            "aws secretsmanager create-secret "
            "--name prod/app/aws-credentials "
            "--secret-string '{\"access_key_id\":\"AKIA...\",\"secret_access_key\":\"...\"}'"
        ),
    },
    "aws_secret_key": {
        "name":    "AWS Secret Access Key",
        "service": "Amazon Web Services (IAM)",
        "risk":    "Together with the Access Key ID this gives complete AWS API access.",
        "rotation_steps": [
            "Rotate together with the AWS Access Key ID — they are always a pair.",
            "Sign in to AWS Console → IAM → Users → Security Credentials.",
            "Create a new access key (a new ID + secret are generated together).",
            "Update AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY everywhere.",
            "Deactivate then delete the old key pair.",
        ],
        "env_var":         "AWS_SECRET_ACCESS_KEY",
        "secrets_manager": (
            "aws secretsmanager create-secret "
            "--name prod/app/aws-credentials "
            "--secret-string '{\"access_key_id\":\"AKIA...\",\"secret_access_key\":\"wJalr...\"}'"
        ),
    },
    "stripe_live_key": {
        "name":    "Stripe Live Secret Key",
        "service": "Stripe Payments",
        "risk":    "Full access to the Stripe account — can create charges, issue refunds, "
                   "access customer PII and payment data.",
        "rotation_steps": [
            "Log in to Stripe Dashboard → Developers → API Keys.",
            "Click 'Roll key…' next to the compromised secret key.",
            "Stripe generates a replacement — copy it immediately (shown once).",
            "Update STRIPE_SECRET_KEY in all environments.",
            "The old key is invalidated immediately upon rolling.",
            "Review Stripe Dashboard → Logs for any suspicious API calls made with the old key.",
        ],
        "env_var":         "STRIPE_SECRET_KEY",
        "secrets_manager": (
            "aws secretsmanager create-secret "
            "--name prod/stripe/secret-key "
            "--secret-string 'sk_live_...'"
        ),
    },
    "stripe_test_key": {
        "name":    "Stripe Test Secret Key",
        "service": "Stripe Payments (Test Mode)",
        "risk":    "Access to test-mode Stripe data; lower risk but should not be in source "
                   "control — attackers may use it to profile your integration.",
        "rotation_steps": [
            "Log in to Stripe Dashboard → toggle to Test Mode → Developers → API Keys.",
            "Click 'Roll key…' next to the compromised test secret key.",
            "Update STRIPE_TEST_SECRET_KEY in development/CI environments.",
            "The old key is invalidated immediately upon rolling.",
        ],
        "env_var":         "STRIPE_TEST_SECRET_KEY",
        "secrets_manager": (
            "aws secretsmanager create-secret "
            "--name dev/stripe/test-secret-key "
            "--secret-string 'sk_test_...'"
        ),
    },
    "github_pat": {
        "name":    "GitHub Personal Access Token",
        "service": "GitHub",
        "risk":    "Can access private repositories, push malicious code, read Actions secrets, "
                   "and access organisation data depending on token scopes.",
        "rotation_steps": [
            "Go to GitHub → Settings → Developer Settings → Personal Access Tokens.",
            "Find the compromised token and click 'Delete'.",
            "Click 'Generate new token' granting only the required minimum scopes.",
            "Update GITHUB_TOKEN in all CI/CD pipelines and applications.",
            "Review: GitHub → Settings → Security Log for recent activity.",
        ],
        "env_var":         "GITHUB_TOKEN",
        "secrets_manager": (
            "aws secretsmanager create-secret "
            "--name prod/github/token "
            "--secret-string 'ghp_...'"
        ),
    },
    "github_oauth": {
        "name":    "GitHub OAuth Token",
        "service": "GitHub (OAuth App)",
        "risk":    "OAuth app access to user/org GitHub data; scope-dependent risk.",
        "rotation_steps": [
            "Go to GitHub → Settings → Applications → Authorized OAuth Apps.",
            "Revoke access for the affected app.",
            "Re-authorise the app to generate a fresh token.",
            "Update GITHUB_OAUTH_TOKEN in the application.",
        ],
        "env_var":         "GITHUB_OAUTH_TOKEN",
        "secrets_manager": (
            "aws secretsmanager create-secret "
            "--name prod/github/oauth-token "
            "--secret-string 'gho_...'"
        ),
    },
    "slack_token": {
        "name":    "Slack Bot / API Token",
        "service": "Slack",
        "risk":    "Can read channel messages, post as the bot, access workspace membership data.",
        "rotation_steps": [
            "Go to api.slack.com/apps → select your app.",
            "Go to OAuth & Permissions → Revoke All OAuth Tokens.",
            "Reinstall the app to your workspace to obtain a fresh token.",
            "Update SLACK_TOKEN in all applications.",
            "Review Slack audit logs (Enterprise Grid) for suspicious activity.",
        ],
        "env_var":         "SLACK_TOKEN",
        "secrets_manager": (
            "aws secretsmanager create-secret "
            "--name prod/slack/token "
            "--secret-string 'xoxb-...'"
        ),
    },
    "jwt_token": {
        "name":    "JWT Signing Secret",
        "service": "Application Authentication",
        "risk":    "Allows forging of authentication tokens — an attacker can impersonate "
                   "any user, including administrators.",
        "rotation_steps": [
            "Generate a new strong secret (≥512 bits): "
            "python3 -c \"import secrets; print(secrets.token_hex(64))\"",
            "Update JWT_SECRET in all environment configs and secrets stores.",
            "All existing sessions are immediately invalidated — schedule during low-traffic.",
            "Deploy the change and monitor for unexpected auth failures.",
        ],
        "env_var":         "JWT_SECRET",
        "secrets_manager": (
            "aws secretsmanager create-secret "
            "--name prod/app/jwt-secret "
            "--secret-string '<output-of-token_hex-above>'"
        ),
    },
    "db_connection_string": {
        "name":    "Database Connection String",
        "service": "Database (MySQL / PostgreSQL / MongoDB / Redis)",
        "risk":    "Direct database access — an attacker can read, modify, or delete all data.",
        "rotation_steps": [
            "Connect to the database with a privileged account.",
            "Create a new application user with the same permissions, e.g.:\n"
            "  PostgreSQL: CREATE USER newapp WITH PASSWORD 'strong-password';\n"
            "              GRANT ALL ON DATABASE mydb TO newapp;",
            "Update DATABASE_URL in all application environments.",
            "Restart the application and verify connections succeed.",
            "Revoke privileges from and drop the old user:\n"
            "  REVOKE ALL ON DATABASE mydb FROM oldapp;\n"
            "  DROP USER oldapp;",
        ],
        "env_var":         "DATABASE_URL",
        "secrets_manager": (
            "aws secretsmanager create-secret "
            "--name prod/db/connection "
            "--secret-string 'postgres://newapp:strong-password@host:5432/mydb'"
        ),
    },
    "hardcoded_password": {
        "name":    "Hardcoded Password",
        "service": "Application / Database / Third-party Service",
        "risk":    "Anyone with code-read access can authenticate directly to the protected resource.",
        "rotation_steps": [
            "Generate a strong replacement password:\n"
            "  python3 -c \"import secrets, string; print(secrets.token_urlsafe(32))\"",
            "Update the password in the target service (database, admin panel, etc.).",
            "Store the new password in an environment variable or secrets manager.",
            "Remove the hardcoded value from source code.",
            "If the secret was ever committed: rewrite git history with BFG Repo Cleaner:\n"
            "  bfg --replace-text passwords.txt && git reflog expire --expire=now --all && git gc --prune=now",
            "Force-push the cleaned history and rotate any deploy keys.",
        ],
        "env_var":         "APP_PASSWORD",
        "secrets_manager": (
            "aws secretsmanager create-secret "
            "--name prod/app/password "
            "--secret-string '<new-strong-password>'"
        ),
    },
    "generic_api_key": {
        "name":    "API Key",
        "service": "Third-party Service",
        "risk":    "Unauthorised access to the third-party service and its data / billing.",
        "rotation_steps": [
            "Log in to the third-party service's developer or API console.",
            "Navigate to API Keys / Credentials.",
            "Generate a new API key.",
            "Update the key in all application environments.",
            "Revoke / delete the old key.",
            "Check the service's audit or access log for activity on the old key.",
        ],
        "env_var":         "API_KEY",
        "secrets_manager": (
            "aws secretsmanager create-secret "
            "--name prod/service/api-key "
            "--secret-string '<new-api-key>'"
        ),
    },
    "generic_secret": {
        "name":    "Secret / Token",
        "service": "Application",
        "risk":    "Unauthorised access to whichever service or data this secret protects.",
        "rotation_steps": [
            "Identify which service this secret authenticates to.",
            "Generate a new secret in that service's console or CLI.",
            "Update all references in application config and CI/CD.",
            "Invalidate / delete the old secret.",
        ],
        "env_var":         "APP_SECRET",
        "secrets_manager": (
            "aws secretsmanager create-secret "
            "--name prod/app/secret "
            "--secret-string '<new-secret>'"
        ),
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# Secret type classifier
# ─────────────────────────────────────────────────────────────────────────────

def _classify_secret(finding: Dict[str, Any]) -> str:
    """
    Returns a SECRET_META key for this finding.

    Strategy (in priority order):
    1. Regex-match the actual secret value (finding["value"] or finding["match"]).
    2. Keyword-match against the combined metadata fields.
    3. Default to "generic_secret".
    """
    # 1 — regex match on the actual leaked value
    secret_value = (
        finding.get("value")
        or finding.get("match")
        or finding.get("secret")
        or ""
    )
    if secret_value:
        for pattern, secret_type in SECRET_PATTERNS:
            if pattern.search(secret_value):
                return secret_type

    # 2 — keyword match on metadata (for findings that don't include the raw value)
    title   = (finding.get("title")       or "").lower()
    rule_id = (finding.get("rule_id")     or "").lower()
    desc    = (finding.get("description") or "").lower()
    fix     = (finding.get("fix_hint")    or "").lower()
    cwe     = (finding.get("cwe")         or "").lower()
    combined = f"{title} {rule_id} {desc} {fix} {cwe}"

    # AWS — check both key types; order matters (access key first)
    if "aws_access_key" in combined or "access key id" in combined or "akia" in combined:
        return "aws_access_key"
    if "aws_secret" in combined or "secret_access_key" in combined:
        return "aws_secret_key"

    # Stripe — distinguish live vs test by looking for the prefix, not the word "live"
    if "stripe" in combined:
        if "sk_live" in combined or "live_key" in combined or "live_secret" in combined:
            return "stripe_live_key"
        return "stripe_test_key"

    # GitHub
    if "github" in combined and any(kw in combined for kw in ("token", "pat", "ghp_", "oauth")):
        if "oauth" in combined:
            return "github_oauth"
        return "github_pat"

    # Slack
    if "slack" in combined:
        return "slack_token"

    # JWT — be specific; avoid matching generic "token" rule_ids
    if "jwt" in combined or "json web token" in combined or "cwe-321" in combined:
        return "jwt_token"

    # Database
    if any(x in combined for x in (
        "mysql", "postgresql", "postgres", "mongodb", "redis", "connection string", "database_url"
    )):
        return "db_connection_string"

    # Password
    if any(x in combined for x in ("password", "passwd", "cwe-259", "cwe-522")):
        return "hardcoded_password"

    # API key
    if any(x in combined for x in ("api_key", "api key", "apikey")):
        return "generic_api_key"

    # Generic secret / credential — NOT just "token" to avoid CSRF/rate-limit false positives
    if any(x in combined for x in ("hardcoded", "secret", "credential", "cwe-798")):
        return "generic_secret"

    return "generic_secret"


def _is_secret_finding(finding: Dict[str, Any]) -> bool:
    """
    Returns True if this finding is about a hardcoded secret.
    Deliberately avoids the bare keyword "token" to reduce false positives
    (e.g. CSRF tokens, pagination tokens).
    """
    if not isinstance(finding, dict):
        return False

    title   = (finding.get("title")   or "").lower()
    rule_id = (finding.get("rule_id") or "").lower()
    cwe     = (finding.get("cwe")     or "").lower()
    combined = f"{title} {rule_id} {cwe}"

    return any(kw in combined for kw in (
        "hardcoded", "secret", "credential", "password", "passwd",
        "api_key", "apikey", "api key",
        "aws_access", "aws_secret",
        "stripe", "github_pat", "slack_token",
        "jwt",
        "cwe-798",  # Use of Hard-coded Credentials
        "cwe-259",  # Use of Hard-coded Password
        "cwe-321",  # Use of Hard-coded Cryptographic Key
        "cwe-522",  # Insufficiently Protected Credentials
    ))


# ─────────────────────────────────────────────────────────────────────────────
# Language detection & replacement-code generation
# ─────────────────────────────────────────────────────────────────────────────

def _detect_lang(filepath: str) -> str:
    fp = filepath.lower()
    if fp.endswith(".py"):                          return "python"
    if fp.endswith((".js", ".mjs", ".cjs")):        return "javascript"
    if fp.endswith((".ts", ".tsx")):                return "typescript"
    if fp.endswith(".php"):                         return "php"
    if fp.endswith(".rb"):                          return "ruby"
    if fp.endswith(".java"):                        return "java"
    if fp.endswith(".go"):                          return "go"
    if fp.endswith(".tf"):                          return "terraform"
    if fp.endswith(".rs"):                          return "rust"
    if ".env" in fp or fp.endswith(".env"):         return "dotenv"
    if fp.endswith((".yaml", ".yml")):              return "yaml"
    return "generic"


def _gen_replacement(lang: str, env_var: str) -> str:
    """Generate idiomatic env-var access code for the detected language."""
    var_name = env_var.lower()   # Pythonic / conventional lowercase variable name

    templates: Dict[str, str] = {
        "python": (
            f"import os\n"
            f"{var_name} = os.environ.get('{env_var}')\n"
            f"if not {var_name}:\n"
            f"    raise RuntimeError(\"Missing required environment variable: {env_var}\")"
        ),
        "javascript": (
            f"// At app startup (after require('dotenv').config())\n"
            f"const {var_name} = process.env.{env_var};\n"
            f"if (!{var_name}) throw new Error('Missing env var: {env_var}');"
        ),
        "typescript": (
            f"// At app startup (after dotenv config)\n"
            f"const {var_name}: string = process.env.{env_var} ?? (() => {{\n"
            f"  throw new Error('Missing env var: {env_var}');\n"
            f"}})();"
        ),
        "php": (
            f"${var_name} = getenv('{env_var}');\n"
            f"if (!${var_name}) throw new \\RuntimeException('Missing env var: {env_var}');"
        ),
        "ruby": (
            f"{var_name} = ENV.fetch('{env_var}') {{ raise \"Missing env var: {env_var}\" }}"
        ),
        "java": (
            f"String {var_name} = System.getenv(\"{env_var}\");\n"
            f"if ({var_name} == null) throw new IllegalStateException(\"Missing env var: {env_var}\");"
        ),
        "go": (
            f'{var_name} := os.Getenv("{env_var}")\n'
            f'if {var_name} == "" {{\n'
            f'    log.Fatalf("missing required environment variable: {env_var}")\n'
            f'}}'
        ),
        "rust": (
            f'let {var_name} = std::env::var("{env_var}")\n'
            f'    .expect("Missing env var: {env_var}");'
        ),
        "terraform": (
            f'# Set via environment variable: export TF_VAR_{var_name}="<value>"\n'
            f'variable "{var_name}" {{\n'
            f'  description = "{env_var} — injected at runtime, never hardcoded"\n'
            f'  sensitive   = true\n'
            f'}}'
        ),
        "dotenv": (
            f"# Do NOT commit .env files containing real secrets.\n"
            f"# Remove the real value; reference only a placeholder:\n"
            f"# {env_var}=REPLACE_ME\n"
            f"# Store the real value in your secrets manager or CI/CD secret store."
        ),
        "yaml": (
            f"# Reference an environment variable rather than inlining the secret:\n"
            f"# {env_var.lower()}: ${{{{ env.{env_var} }}}}"
        ),
        "generic": (
            f"# Replace the hardcoded value with an environment variable.\n"
            f"# Export in your shell or CI/CD environment:\n"
            f"#   export {env_var}='<real-value>'\n"
            f"# Then reference it as: ${env_var}"
        ),
    }
    return templates.get(lang, templates["generic"])


# ─────────────────────────────────────────────────────────────────────────────
# Urgency mapping
# ─────────────────────────────────────────────────────────────────────────────

_URGENCY: Dict[str, str] = {
    "CRITICAL": "Rotate immediately — treat as a live breach until rotated.",
    "HIGH":     "Rotate within 24 hours.",
    "MEDIUM":   "Rotate within 1 week.",
    "LOW":      "Rotate at the next scheduled maintenance window.",
    "INFO":     "Low risk; rotate at your earliest convenience.",
}


def _urgency(severity: str) -> str:
    return _URGENCY.get((severity or "").upper(), "Rotate as soon as possible.")


# ─────────────────────────────────────────────────────────────────────────────
# Build advisor entry for one finding
# ─────────────────────────────────────────────────────────────────────────────

def _build_advice(finding: Dict[str, Any]) -> Dict[str, Any]:
    secret_type = _classify_secret(finding)
    # Always guaranteed to exist; _classify_secret never returns an unknown key
    meta = SECRET_META[secret_type]

    file_str = finding.get("file") or "unknown"
    lang     = _detect_lang(file_str)
    env_var  = meta["env_var"]

    return {
        "finding_id":       finding.get("id", ""),
        "finding_title":    finding.get("title", ""),
        "file":             file_str,
        "line":             finding.get("line"),
        "severity":         (finding.get("severity") or "").upper(),
        "secret_type":      secret_type,
        "secret_name":      meta["name"],
        "service":          meta["service"],
        "risk":             meta["risk"],
        "rotation_steps":   meta["rotation_steps"],
        "env_var":          env_var,
        "replacement_code": _gen_replacement(lang, env_var),
        "secrets_manager":  meta["secrets_manager"],
        "urgency":          _urgency(finding.get("severity", "")),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Public entry point
# ─────────────────────────────────────────────────────────────────────────────

def build_secret_advisor(scan: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build rotation runbooks for all secret findings in a scan result dict.

    Expected scan structure:
    {
        "scan_id":  str,
        "repo":     str,
        "findings": [
            {
                "id":          str,
                "title":       str,
                "rule_id":     str,
                "description": str,
                "file":        str,
                "line":        int | None,
                "severity":    "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
                "cwe":         str | None,
                "fix_hint":    str | None,
                # Optional — used for more accurate regex-based classification:
                "value":       str | None,   # the actual leaked secret
                "match":       str | None,   # raw matched text
            },
            ...
        ]
    }
    """
    if not isinstance(scan, dict):
        raise TypeError(f"Expected scan to be a dict, got {type(scan).__name__}")

    findings_raw = scan.get("findings")
    if findings_raw is None:
        findings_raw = []
    if not isinstance(findings_raw, list):
        raise TypeError(
            f"scan['findings'] must be a list, got {type(findings_raw).__name__}"
        )

    secret_findings = [f for f in findings_raw if _is_secret_finding(f)]

    if not secret_findings:
        return {
            "scan_id":    scan.get("scan_id", ""),
            "repo":       scan.get("repo", ""),
            "count":      0,
            "critical":   0,
            "high":       0,
            "advisories": [],
            "summary":    "No hardcoded secrets found in this scan.",
        }

    advisories = [_build_advice(f) for f in secret_findings]

    # Sort: CRITICAL → HIGH → MEDIUM → LOW → INFO → unknown
    _SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    advisories.sort(key=lambda a: _SEV_ORDER.get(a["severity"], 99))

    critical_count = sum(1 for a in advisories if a["severity"] == "CRITICAL")
    high_count     = sum(1 for a in advisories if a["severity"] == "HIGH")
    total          = len(advisories)

    return {
        "scan_id":    scan.get("scan_id", ""),
        "repo":       scan.get("repo", ""),
        "count":      total,
        "critical":   critical_count,
        "high":       high_count,
        "advisories": advisories,
        "summary": (
            f"{total} secret finding{'s' if total != 1 else ''} require rotation. "
            f"{critical_count} critical — rotate immediately. "
            f"Follow each runbook in order."
        ),
    }