"""
AI remediation engine.
Primary:  Groq (llama-3.3-70b-versatile)
Fallback: AWS Bedrock (Claude Sonnet 4.6)
"""
import os
import json
import re
from dotenv import load_dotenv
load_dotenv()
from itertools import cycle
from typing import List, Optional
from models import Finding, AttackChain, ScanResult, Severity


def _strip_json(raw: str) -> str:
    """Strip markdown fences and sanitize control characters that AI models sometimes emit."""
    raw = raw.strip()
    raw = re.sub(r"^```(?:json)?\s*", "", raw, flags=re.MULTILINE)
    raw = re.sub(r"\s*```\s*$", "", raw, flags=re.MULTILINE)
    raw = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", raw)
    return raw.strip()


# ---------------------------------------------------------------------------
# Groq key cycling
# ---------------------------------------------------------------------------

def _load_groq_keys() -> list[str]:
    """
    Load up to 6 Groq API keys from env vars:
      GROQ_API_KEY_1 … GROQ_API_KEY_6
    Falls back to the legacy GROQ_API_KEY if none of the numbered ones are set.
    """
    keys = []
    for i in range(1, 7):
        k = os.getenv(f"GROQ_API_KEY_{i}", "").strip()
        if k:
            keys.append(k)
    if not keys:
        fallback = os.getenv("GROQ_API_KEY", "").strip()
        if fallback:
            keys.append(fallback)
    return keys


_GROQ_KEYS: list[str] = _load_groq_keys()
_GROQ_KEY_CYCLE = cycle(_GROQ_KEYS) if _GROQ_KEYS else iter([])
_groq_call_count = 0


def _next_groq_key() -> str:
    """Return the next key in the round-robin rotation."""
    if not _GROQ_KEYS:
        raise RuntimeError("No Groq API keys configured.")
    return next(_GROQ_KEY_CYCLE)


def _call_bedrock(prompt: str, system: str = "", max_tokens: int = 1024) -> str:
    import boto3
    client = boto3.client(
        "bedrock-runtime",
        region_name=os.getenv("AWS_REGION", "us-east-1"),
    )
    body: dict = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt}],
    }
    if system:
        body["system"] = system

    response = client.invoke_model(
        modelId="us.anthropic.claude-sonnet-4-6",
        body=json.dumps(body),
        contentType="application/json",
        accept="application/json",
    )
    result = json.loads(response["body"].read())
    return result["content"][0]["text"]


def _call_groq(prompt: str, system: str = "", max_tokens: int = 1024) -> str:
    global _groq_call_count
    from groq import Groq  # type: ignore

    api_key = _next_groq_key()
    _groq_call_count += 1
    key_index = (_groq_call_count - 1) % len(_GROQ_KEYS) + 1
    print(f"[Groq] Using key slot {key_index}/{len(_GROQ_KEYS)} (call #{_groq_call_count})")

    client = Groq(api_key=api_key)
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    resp = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=messages,
        max_tokens=max_tokens,
        temperature=0.1,
    )
    return resp.choices[0].message.content


def call_ai(prompt: str, system: str = "", max_tokens: int = 1024) -> str:
    """Try Groq first, fall back to AWS Bedrock."""
    try:
        result = _call_groq(prompt, system, max_tokens)
        print("[AI] Used Groq")
        return result
    except Exception as e:
        print(f"[AI] Groq failed ({type(e).__name__}: {e}), falling back to Bedrock")
        return _call_bedrock(prompt, system, max_tokens)


REMEDIATION_SYSTEM = (
    "You are a senior cloud security engineer. "
    "Explain vulnerabilities clearly and provide exact, copy-paste-ready fixes. "
    "Be precise and concise. ALWAYS respond with valid JSON only — no markdown, no preamble."
)


def remediate_finding(finding: Finding, file_content: Optional[str] = None) -> None:
    """Enrich a finding in-place with AI-generated fix and explanation."""
    context = ""
    if file_content:
        if finding.line and finding.line > 20:
            lines = file_content.splitlines()
            start = max(0, finding.line - 15)
            end   = min(len(lines), finding.line + 15)
            snippet = "\n".join(lines[start:end])
        else:
            snippet = file_content[:2000]
        context = f"\n\nRelevant file content (around line {finding.line}):\n```\n{snippet}\n```"

    prompt = (
        f"Analyze this security finding and provide a fix.\n\n"
        f"Finding:\n"
        f"- Domain: {finding.domain}\n"
        f"- Severity: {finding.severity}\n"
        f"- Title: {finding.title}\n"
        f"- Description: {finding.description}\n"
        f"- File: {finding.file or 'N/A'}\n"
        f"- Line: {finding.line or 'N/A'}\n"
        f"- Rule: {finding.rule_id or 'N/A'}"
        f"{context}\n\n"
        f"Respond ONLY with this JSON:\n"
        f'{{"fix_hint":"one sentence fix","fixed_code":"exact corrected snippet or null","explanation":"2-3 sentence technical explanation"}}'
    )

    try:
        raw  = call_ai(prompt, REMEDIATION_SYSTEM, max_tokens=900)
        data = json.loads(_strip_json(raw))

        fix_hint    = data.get("fix_hint")
        fixed_code  = data.get("fixed_code")
        explanation = data.get("explanation")

        if fix_hint and isinstance(fix_hint, str):
            finding.fix_hint = fix_hint.strip()
        if fixed_code and isinstance(fixed_code, str) and fixed_code.lower() != "null":
            finding.fixed_code = fixed_code.strip()
        if explanation and isinstance(explanation, str):
            finding.description = explanation.strip()

    except json.JSONDecodeError as e:
        print(f"[AI] JSON parse failed for finding {finding.id}: {e}")
        finding.fix_hint = "Automated fix unavailable — review manually."
    except Exception as e:
        print(f"[AI] Remediation failed for finding {finding.id}: {type(e).__name__}: {e}")
        finding.fix_hint = "Automated fix unavailable — review manually."


CHAIN_SYSTEM = (
    "You are a threat modelling expert specialising in cloud security. "
    "Identify how separate vulnerabilities combine into complete attack chains. "
    "ALWAYS respond with valid JSON only — no markdown, no preamble."
)


def build_attack_chains(findings: List[Finding]) -> List[AttackChain]:
    """Use AI to identify multi-domain attack chains across findings."""
    if len(findings) < 2:
        return []

    summary = [
        {
            "id":       f.id,
            "domain":   f.domain,
            "severity": f.severity,
            "title":    f.title,
            "file":     f.file,
        }
        for f in findings[:30]
    ]

    domains_present = sorted(set(f["domain"] for f in summary))
    prompt = (
        "You are given security findings from a cloud repository scan.\n"
        "Your job: identify ATTACK CHAINS — scenarios where 2+ findings combine "
        "so an attacker can move from initial access to a significant impact (data "
        "exfiltration, privilege escalation, full system compromise).\n\n"
        f"Domains found: {', '.join(domains_present)}\n"
        f"Findings:\n{json.dumps(summary, indent=2)}\n\n"
        "Chain quality rules:\n"
        "- A good chain has a clear ATTACKER NARRATIVE: what they do step by step\n"
        "- Prefer chains that cross domains (CODE + IAC = attacker reads code secrets "
        "  then accesses cloud infra; IAM + CODE = escalate then exfiltrate)\n"
        "- If only CODE findings exist, chain finding types: e.g. phpinfo reveals DB "
        "  config -> SQLi extracts credentials -> RCE via exec achieves persistence\n"
        "- Steps must be concrete: name the specific finding, file, and what the "
        "  attacker gains. Avoid vague steps like 'attacker gains access'.\n"
        "- risk_score: 90-100 = no skill required + critical data lost; 70-89 = "
        "  moderate skill; 50-69 = skilled attacker only\n"
        "- Maximum 3 chains, minimum 2 findings per chain\n"
        "- finding_ids must exactly match IDs in the list above\n"
        "- remediation must be the ONE fix that breaks the chain (the weakest link)\n\n"
        'Respond ONLY with valid JSON: {"chains":[{"title":"short name","risk_score":95,'
        '"description":"2-3 sentence breach scenario from attacker perspective","steps":'
        '["Step 1: attacker does X using finding Y in file Z","Step 2: this gives them W"],'
        '"finding_ids":["id1","id2"],"remediation":"exact fix to break this chain"}]}'
    )

    try:
        raw  = call_ai(prompt, CHAIN_SYSTEM, max_tokens=1800)
        data = json.loads(_strip_json(raw))

        chains: List[AttackChain] = []
        valid_ids = {f.id for f in findings}

        for c in data.get("chains", []):
            if not isinstance(c, dict):
                continue
            title       = c.get("title", "Unknown Chain")
            risk_score  = max(0, min(100, int(c.get("risk_score", 80))))
            description = c.get("description", "")
            steps       = [s for s in c.get("steps", []) if isinstance(s, str)]
            finding_ids = [fid for fid in c.get("finding_ids", []) if fid in valid_ids]
            remediation = c.get("remediation", "")

            if not title or not description:
                continue

            if len(finding_ids) < 2:
                print(f"[AI] Dropped chain '{title}' — fewer than 2 valid finding_ids")
                continue

            chains.append(AttackChain(
                title        = title,
                risk_score   = risk_score,
                description  = description,
                steps        = steps,
                finding_ids  = finding_ids,
                remediation  = remediation,
            ))

        return chains

    except json.JSONDecodeError as e:
        print(f"[AI] Attack chain JSON parse failed: {e}")
        return []
    except Exception as e:
        print(f"[AI] Attack chain generation failed: {type(e).__name__}: {e}")
        return []


_SEV_ORDER = {
    Severity.CRITICAL.value: 0,
    Severity.HIGH.value:     1,
    Severity.MEDIUM.value:   2,
    Severity.LOW.value:      3,
    Severity.INFO.value:     4,
}


def enrich_scan(result: ScanResult, repo_path: str) -> ScanResult:
    """Sort findings, run AI remediation on unique rule types, build attack chains."""

    result.findings.sort(key=lambda f: _SEV_ORDER.get(f.severity, 99))

    seen_rules: set = set()
    priority: list  = []
    remainder: list = []

    for f in result.findings:
        key = f.rule_id or f.title
        if key not in seen_rules:
            seen_rules.add(key)
            priority.append(f)
        else:
            remainder.append(f)

    to_remediate = (priority + remainder)[:40]

    for finding in to_remediate:
        file_content: Optional[str] = None
        if finding.file and repo_path:
            full_path = os.path.join(repo_path, finding.file)
            try:
                with open(full_path, encoding="utf-8", errors="ignore") as fp:
                    file_content = fp.read()
            except OSError:
                pass
        remediate_finding(finding, file_content)

    rule_to_fix: dict = {}
    for f in to_remediate:
        key = f.rule_id or f.title
        if f.fix_hint and key not in rule_to_fix:
            rule_to_fix[key] = (f.fix_hint, f.fixed_code, f.description)

    for f in result.findings:
        key = f.rule_id or f.title
        if not f.fix_hint and key in rule_to_fix:
            hint, code, desc = rule_to_fix[key]
            f.fix_hint   = hint
            f.fixed_code = code

    result.attack_chains = build_attack_chains(result.findings[:30])

    return result