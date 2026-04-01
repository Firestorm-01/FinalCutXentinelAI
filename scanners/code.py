import subprocess
import json
import os
import re
import tempfile
from typing import List
from models import Finding, Severity, Domain

RULESETS = [
    "p/owasp-top-ten",
    "p/secrets",
    "p/javascript",
    "p/python",
    "p/nodejs",
    "p/sql-injection",
    "p/xss",
]

SEV_MAP = {
    "ERROR":   Severity.CRITICAL.value,
    "WARNING": Severity.HIGH.value,
    "INFO":    Severity.MEDIUM.value,
}

INLINE_RULES = r"""
rules:
  - id: xentinel-hardcoded-aws-access-key
    pattern-regex: 'AKIA[0-9A-Z]{16}'
    message: Hardcoded AWS Access Key ID detected
    languages: [generic]
    severity: ERROR
    metadata:
      cwe: CWE-798
      owasp: A02:2021

  - id: xentinel-hardcoded-aws-secret
    pattern-regex: '(?i)(aws_secret_access_key|aws_secret|secret_access_key)\s*[=:]\s*["\x27]?[A-Za-z0-9/+=]{40}["\x27]?'
    message: Hardcoded AWS Secret Access Key detected
    languages: [generic]
    severity: ERROR
    metadata:
      cwe: CWE-798

  - id: xentinel-hardcoded-credential
    pattern-regex: '(?i)(api_key|apikey|api_secret|auth_token|access_token|private_key)\s*[=:]\s*["\x27][A-Za-z0-9!@#$%^&*()_+\-=]{12,}["\x27]'
    message: Hardcoded API key or token detected
    languages: [generic]
    severity: ERROR
    metadata:
      cwe: CWE-259

  - id: xentinel-cors-wildcard
    pattern-regex: '(?i)access.control.allow.origin\s*[=:]\s*["\x27]?\*'
    message: CORS wildcard origin allows any domain
    languages: [generic]
    severity: WARNING
    metadata:
      cwe: CWE-942

  - id: xentinel-sql-injection-format
    pattern-regex: '(?i)(select|insert|update|delete)\s+.*(%s|%d|\$\{.*\}|f".*\{)'
    message: Potential SQL injection via string formatting
    languages: [python, javascript, java]
    severity: ERROR
    metadata:
      cwe: CWE-89
"""

EXCLUDE_FRAGMENTS = [
    "impossible.php",
    "/vendor/",
    "/node_modules/",
    "/.git/",
    "/test/",
    "/tests/",
    ".min.js",
]


def _is_excluded(path: str) -> bool:
    for frag in EXCLUDE_FRAGMENTS:
        if frag in path:
            return True
    return False


def _clean_rule_id(raw_id: str) -> str:
    if not raw_id:
        return raw_id
    match = re.search(r'(xentinel-[a-z0-9\-]+)$', raw_id)
    if match:
        return match.group(1)
    return raw_id


def run(repo_path: str) -> List[Finding]:
    findings: List[Finding] = []

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yml",
                                     prefix="xentinel_rules_", delete=False) as tf:
        tf.write(INLINE_RULES)
        rules_path = tf.name

    configs = [f"--config={r}" for r in RULESETS] + [f"--config={rules_path}"]

    cmd = [
        "semgrep", "scan",
        "--json",
        "--no-git-ignore",
        "--timeout", "30",
        "--max-target-bytes", "1000000",
        "--metrics=off",
        *configs,
        repo_path,
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        stdout = result.stdout.strip()
        if not stdout:
            return []
        data = json.loads(stdout)
    except subprocess.TimeoutExpired:
        print("[CODE SCANNER] Semgrep timed out")
        return []
    except json.JSONDecodeError as e:
        print(f"[CODE SCANNER] JSON parse error: {e}")
        return []
    except FileNotFoundError:
        print("[CODE SCANNER] semgrep not found — install: pip install semgrep")
        return []
    finally:
        try:
            os.unlink(rules_path)
        except OSError:
            pass

    for r in data.get("results", []):
        extra    = r.get("extra", {})
        sev_str  = extra.get("severity", "INFO").upper()
        severity = SEV_MAP.get(sev_str, Severity.MEDIUM.value)
        meta     = extra.get("metadata", {})

        raw_path = r.get("path", "")
        rel_path = raw_path[len(repo_path):].lstrip("/\\") if raw_path.startswith(repo_path) else raw_path

        if _is_excluded(rel_path):
            continue

        raw_rule_id   = r.get("check_id", "unknown")
        clean_rule_id = _clean_rule_id(raw_rule_id)

        cwe_raw = meta.get("cwe")
        cwe = cwe_raw if isinstance(cwe_raw, str) else (cwe_raw[0] if isinstance(cwe_raw, list) and cwe_raw else None)

        findings.append(Finding(
            domain      = Domain.CODE.value,
            severity    = severity,
            title       = clean_rule_id.split(".")[-1].replace("-", " ").title(),
            description = extra.get("message", "No description available"),
            file        = rel_path or None,
            line        = r.get("start", {}).get("line"),
            rule_id     = clean_rule_id,
            cwe         = cwe,
        ))

    # Deduplicate by (rule_id, file, line)
    seen: set = set()
    unique: List[Finding] = []
    for f in findings:
        key = (f.rule_id, f.file, f.line)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    print(f"[CODE SCANNER] {len(unique)} findings ({len(findings) - len(unique)} dupes removed)")
    return unique
