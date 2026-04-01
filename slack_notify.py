"""
XentinelAI — Slack Notification
Sends a rich formatted message to a Slack webhook on every scan completion.
Requires SLACK_WEBHOOK_URL in .env

Drop-in: no changes to existing files except main.py (one call added).
"""

import json
import os
import urllib.request
import urllib.error
from typing import Optional


def _post_webhook(webhook_url: str, payload: dict) -> None:
    data = json.dumps(payload).encode()
    req  = urllib.request.Request(
        webhook_url,
        data=data,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status != 200:
                print(f"[Slack] Unexpected status: {resp.status}")
    except urllib.error.HTTPError as e:
        print(f"[Slack] HTTP error: {e.code} {e.reason}")
    except Exception as e:
        print(f"[Slack] Failed: {type(e).__name__}: {e}")


def _severity_bar(critical: int, high: int, medium: int, low: int) -> str:
    """Build a compact visual severity bar."""
    parts = []
    if critical: parts.append(f"🔴 *{critical} Critical*")
    if high:     parts.append(f"🟠 *{high} High*")
    if medium:   parts.append(f"🟡 {medium} Medium")
    if low:      parts.append(f"🟢 {low} Low")
    return "  ·  ".join(parts) if parts else "✅ No findings"


def _risk_emoji(score: int) -> str:
    if score >= 90: return "🚨"
    if score >= 70: return "⚠️"
    return "ℹ️"


def notify_scan_complete(
    scan_id:       str,
    repo:          str,
    scanned_at:    str,
    stats:         dict,
    attack_chains: list,
    dashboard_url: Optional[str] = None,
) -> None:
    """
    Send a Slack notification for a completed scan.
    Safe to call — silently no-ops if SLACK_WEBHOOK_URL is not set.
    """
    webhook_url = os.getenv("SLACK_WEBHOOK_URL", "").strip()
    if not webhook_url:
        return

    total    = stats.get("total", 0)
    critical = stats.get("critical", 0)
    high     = stats.get("high", 0)
    medium   = stats.get("medium", 0)
    low      = stats.get("low", 0)
    chains   = len(attack_chains)

    # Overall risk level
    if critical > 0:
        risk_level = "CRITICAL RISK"
        header_emoji = "🚨"
        color = "#FF1E3C"
    elif high > 0:
        risk_level = "HIGH RISK"
        header_emoji = "⚠️"
        color = "#FF6A00"
    elif medium > 0:
        risk_level = "MEDIUM RISK"
        header_emoji = "🟡"
        color = "#FFCC00"
    else:
        risk_level = "LOW RISK"
        header_emoji = "✅"
        color = "#00E87A"

    # Top attack chain
    chain_section = ""
    if attack_chains:
        top = max(attack_chains, key=lambda c: c.get("risk_score", 0))
        chain_section = (
            f"*Top Attack Chain:* {_risk_emoji(top.get('risk_score', 0))} "
            f"{top.get('title', 'Unknown')}  —  "
            f"Risk Score `{top.get('risk_score', 0)}/100`\n"
            f"_{top.get('description', '')[:120]}..._"
        )

    # Domain breakdown
    by_domain = stats.get("by_domain", {})
    domain_parts = [f"`{d}`: {v}" for d, v in by_domain.items() if v > 0]
    domain_str = "  ·  ".join(domain_parts) if domain_parts else "—"

    # Scan time (clean up ISO string)
    scan_time = scanned_at.replace("T", " ").split(".")[0] + " UTC"

    # Action button
    actions = []
    if dashboard_url:
        actions = [{
            "type": "button",
            "text": {"type": "plain_text", "text": "View Dashboard →"},
            "url": dashboard_url,
            "style": "danger" if critical > 0 else "primary",
        }]

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{header_emoji}  XentinelAI — {risk_level}",
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Repository*\n`{repo}`"},
                {"type": "mrkdwn", "text": f"*Scan ID*\n`{scan_id[:8]}...`"},
                {"type": "mrkdwn", "text": f"*Scanned At*\n{scan_time}"},
                {"type": "mrkdwn", "text": f"*Total Findings*\n`{total}`"},
            ],
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"*Severity Breakdown*\n"
                    f"{_severity_bar(critical, high, medium, low)}\n\n"
                    f"*Domains*\n{domain_str}\n\n"
                    f"*Attack Chains Detected*\n"
                    f"{'`' + str(chains) + '` chain' + ('s' if chains != 1 else '') + ' identified' if chains else '✅ No attack chains detected'}"
                ),
            },
        },
    ]

    if chain_section:
        blocks += [
            {"type": "divider"},
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": chain_section},
            },
        ]

    if actions:
        blocks.append({
            "type": "actions",
            "elements": actions,
        })

    blocks.append({
        "type": "context",
        "elements": [
            {
                "type": "mrkdwn",
                "text": f"XentinelAI · Automated Security Review · Scan `{scan_id}`",
            }
        ],
    })

    payload = {
        "text": f"{header_emoji} XentinelAI scan complete — {repo} · {total} findings · {risk_level}",
        "attachments": [
            {
                "color":  color,
                "blocks": blocks,
            }
        ],
    }

    _post_webhook(webhook_url, payload)
    print(f"[Slack] Notification sent for scan {scan_id}")