"""
XentinelAI — PDF Report Generator
Generates a compact, professional security report from a scan result dict.

Dependencies: reportlab (pip install reportlab)
Endpoint added to main.py: GET /scan/{scan_id}/pdf

Drop-in: no changes to existing files except main.py (one endpoint added).
"""

import io
from datetime import datetime
from typing import Dict, Any, List

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib.colors import (
    HexColor, white, black, Color
)
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak, KeepTogether
)
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT


# ─── Colour palette ───────────────────────────────────────────────────────────
BG          = HexColor("#050608")
SURFACE     = HexColor("#0d1117")
ACCENT      = HexColor("#63ffb4")
RED         = HexColor("#ff4d6d")
ORANGE      = HexColor("#ffd166")
BLUE        = HexColor("#4da6ff")
MUTED       = HexColor("#a9acb0")
TEXT        = HexColor("#e8edf5")
WHITE       = white
DARK_RULE   = HexColor("#1a2a3a")

SEV_COLORS = {
    "CRITICAL": HexColor("#ff4d6d"),
    "HIGH":     HexColor("#ffd166"),
    "MEDIUM":   HexColor("#4da6ff"),
    "LOW":      HexColor("#63ffb4"),
    "INFO":     HexColor("#a9acb0"),
}

SEV_BG = {
    "CRITICAL": HexColor("#2a0d14"),
    "HIGH":     HexColor("#2a2000"),
    "MEDIUM":   HexColor("#0a1a2a"),
    "LOW":      HexColor("#0a2a1a"),
    "INFO":     HexColor("#1a1a1a"),
}

PAGE_W, PAGE_H = A4
MARGIN = 18 * mm


# ─── Styles ───────────────────────────────────────────────────────────────────

def _styles():
    return {
        "h1": ParagraphStyle("h1",
            fontName="Helvetica-Bold", fontSize=26,
            textColor=TEXT, leading=32, spaceAfter=4),

        "h2": ParagraphStyle("h2",
            fontName="Helvetica-Bold", fontSize=14,
            textColor=ACCENT, leading=18, spaceBefore=14, spaceAfter=6),

        "h3": ParagraphStyle("h3",
            fontName="Helvetica-Bold", fontSize=11,
            textColor=TEXT, leading=14, spaceBefore=8, spaceAfter=4),

        "body": ParagraphStyle("body",
            fontName="Helvetica", fontSize=9,
            textColor=MUTED, leading=13, spaceAfter=4),

        "mono": ParagraphStyle("mono",
            fontName="Courier", fontSize=8,
            textColor=ACCENT, leading=12, spaceAfter=2),

        "mono_muted": ParagraphStyle("mono_muted",
            fontName="Courier", fontSize=8,
            textColor=MUTED, leading=12),

        "label": ParagraphStyle("label",
            fontName="Helvetica-Bold", fontSize=8,
            textColor=MUTED, leading=10, spaceAfter=2),

        "tag": ParagraphStyle("tag",
            fontName="Helvetica-Bold", fontSize=8,
            textColor=WHITE, leading=10),

        "footer": ParagraphStyle("footer",
            fontName="Helvetica", fontSize=7,
            textColor=MUTED, leading=10, alignment=TA_CENTER),

        "center": ParagraphStyle("center",
            fontName="Helvetica", fontSize=9,
            textColor=MUTED, leading=13, alignment=TA_CENTER),

        "cover_sub": ParagraphStyle("cover_sub",
            fontName="Helvetica", fontSize=11,
            textColor=MUTED, leading=16, alignment=TA_CENTER),

        "cover_title": ParagraphStyle("cover_title",
            fontName="Helvetica-Bold", fontSize=32,
            textColor=TEXT, leading=38, alignment=TA_CENTER),

        "cover_accent": ParagraphStyle("cover_accent",
            fontName="Helvetica-Bold", fontSize=32,
            textColor=ACCENT, leading=38, alignment=TA_CENTER),
    }


def _rule(color=DARK_RULE, thickness=0.5):
    return HRFlowable(
        width="100%", thickness=thickness,
        color=color, spaceAfter=8, spaceBefore=4
    )


def _sev_pill(severity: str, s) -> Paragraph:
    color = SEV_COLORS.get(severity, MUTED)
    hex_c = color.hexval() if hasattr(color, 'hexval') else "#a9acb0"
    return Paragraph(
        f'<font color="{hex_c}"><b>{severity}</b></font>',
        s["tag"]
    )


# ─── Page template ────────────────────────────────────────────────────────────

class _PageTemplate:
    def __init__(self, repo: str, scan_id: str, total: int):
        self.repo     = repo
        self.scan_id  = scan_id
        self.total    = total

    def on_page(self, canvas, doc):
        canvas.saveState()
        w, h = A4

        # Dark header bar
        canvas.setFillColor(SURFACE)
        canvas.rect(0, h - 14*mm, w, 14*mm, fill=1, stroke=0)

        # Header text
        canvas.setFont("Helvetica-Bold", 8)
        canvas.setFillColor(ACCENT)
        canvas.drawString(MARGIN, h - 9*mm, "XentinelAI")
        canvas.setFillColor(MUTED)
        canvas.setFont("Helvetica", 8)
        canvas.drawString(MARGIN + 48, h - 9*mm, f"Security Report  ·  {self.repo}")
        canvas.drawRightString(w - MARGIN, h - 9*mm, f"Scan {self.scan_id[:8]}...")

        # Footer bar
        canvas.setFillColor(SURFACE)
        canvas.rect(0, 0, w, 10*mm, fill=1, stroke=0)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(MUTED)
        canvas.drawCentredString(w / 2, 4*mm,
            f"XentinelAI Automated Security Review  ·  Page {doc.page}")

        canvas.restoreState()


# ─── Cover page ───────────────────────────────────────────────────────────────

def _cover(scan: Dict[str, Any], s) -> List:
    story = []
    repo       = scan.get("repo", "Unknown")
    scan_id    = scan.get("scan_id", "")
    scanned_at = scan.get("scanned_at", "").replace("T", " ").split(".")[0]
    stats      = scan.get("stats", {})
    critical   = stats.get("critical", 0)
    total      = stats.get("total", 0)
    chains     = len(scan.get("attack_chains", []))

    story.append(Spacer(1, 40*mm))
    story.append(Paragraph("XentinelAI", s["cover_accent"]))
    story.append(Paragraph("Security Scan Report", s["cover_title"]))
    story.append(Spacer(1, 8*mm))
    story.append(_rule(ACCENT, 1))
    story.append(Spacer(1, 6*mm))
    story.append(Paragraph(f"Repository: <b>{repo}</b>", s["cover_sub"]))
    story.append(Spacer(1, 3*mm))
    story.append(Paragraph(f"Scanned: {scanned_at} UTC", s["cover_sub"]))
    story.append(Spacer(1, 3*mm))
    story.append(Paragraph(f"Scan ID: {scan_id}", s["cover_sub"]))
    story.append(Spacer(1, 12*mm))

    # Risk level badge
    if critical > 0:
        risk_txt   = "CRITICAL RISK"
        risk_color = RED
    elif stats.get("high", 0) > 0:
        risk_txt   = "HIGH RISK"
        risk_color = ORANGE
    elif stats.get("medium", 0) > 0:
        risk_txt   = "MEDIUM RISK"
        risk_color = BLUE
    else:
        risk_txt   = "LOW RISK"
        risk_color = ACCENT

    tbl = Table([[Paragraph(risk_txt,
        ParagraphStyle("rl", fontName="Helvetica-Bold", fontSize=13,
                       textColor=WHITE, alignment=TA_CENTER))]],
        colWidths=[60*mm], rowHeights=[12*mm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), risk_color),
        ("ALIGN",      (0,0), (-1,-1), "CENTER"),
        ("VALIGN",     (0,0), (-1,-1), "MIDDLE"),
        ("ROUNDEDCORNERS", [3]),
    ]))
    story.append(tbl)
    story.append(Spacer(1, 14*mm))

    # Quick stats row
    stats_data = [
        [_stat_cell(str(total),    "Total Findings", s),
         _stat_cell(str(critical), "Critical",       s, RED),
         _stat_cell(str(stats.get("high",0)),   "High",   s, ORANGE),
         _stat_cell(str(stats.get("medium",0)), "Medium", s, BLUE),
         _stat_cell(str(chains),   "Attack Chains",  s, ACCENT)],
    ]
    stat_tbl = Table(stats_data, colWidths=[34*mm]*5)
    stat_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), SURFACE),
        ("BOX",        (0,0), (-1,-1), 0.5, DARK_RULE),
        ("INNERGRID",  (0,0), (-1,-1), 0.5, DARK_RULE),
        ("ALIGN",      (0,0), (-1,-1), "CENTER"),
        ("VALIGN",     (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING", (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
    ]))
    story.append(stat_tbl)
    story.append(PageBreak())
    return story


def _stat_cell(value: str, label: str, s, color=TEXT):
    hex_c = color.hexval() if hasattr(color, "hexval") else "#e8edf5"
    return Paragraph(
        f'<font color="{hex_c}" size="18"><b>{value}</b></font><br/>'
        f'<font color="#a9acb0" size="7">{label}</font>',
        ParagraphStyle("sc", fontName="Helvetica", fontSize=9,
                       alignment=TA_CENTER, leading=14)
    )


# ─── Executive summary ────────────────────────────────────────────────────────

def _summary(scan: Dict[str, Any], s) -> List:
    story = []
    stats  = scan.get("stats", {})
    chains = scan.get("attack_chains", [])

    story.append(Paragraph("Executive Summary", s["h2"]))
    story.append(_rule())

    by_domain = stats.get("by_domain", {})
    domain_str = "  ·  ".join(
        f"{d}: {v}" for d, v in by_domain.items() if v > 0
    ) or "No domain data"

    story.append(Paragraph(
        f"This report summarises the automated security review of <b>{scan.get('repo','?')}</b>. "
        f"The scan identified <b>{stats.get('total',0)} findings</b> across "
        f"{sum(1 for v in by_domain.values() if v > 0)} domain(s): {domain_str}. "
        f"<b>{stats.get('critical',0)} critical</b> and "
        f"<b>{stats.get('high',0)} high</b> severity issues require immediate attention.",
        s["body"]
    ))
    story.append(Spacer(1, 4*mm))

    # Domain breakdown table
    domain_rows = [
        [Paragraph("<b>Domain</b>", s["label"]),
         Paragraph("<b>Findings</b>", s["label"]),
         Paragraph("<b>Risk Level</b>", s["label"])],
    ]
    for domain, count in by_domain.items():
        if count == 0:
            continue
        domain_rows.append([
            Paragraph(domain, s["mono"]),
            Paragraph(str(count), s["body"]),
            Paragraph(_domain_risk(domain, count), s["body"]),
        ])

    if len(domain_rows) > 1:
        dtbl = Table(domain_rows, colWidths=[50*mm, 30*mm, 90*mm])
        dtbl.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0),  SURFACE),
            ("BACKGROUND",    (0,1), (-1,-1), HexColor("#080b10")),
            ("TEXTCOLOR",     (0,0), (-1,-1), TEXT),
            ("GRID",          (0,0), (-1,-1), 0.4, DARK_RULE),
            ("TOPPADDING",    (0,0), (-1,-1), 5),
            ("BOTTOMPADDING", (0,0), (-1,-1), 5),
            ("LEFTPADDING",   (0,0), (-1,-1), 6),
        ]))
        story.append(dtbl)

    if chains:
        story.append(Spacer(1, 5*mm))
        story.append(Paragraph(
            f"The AI engine identified <b>{len(chains)} attack chain(s)</b> — "
            "multi-step exploitation paths where separate vulnerabilities combine "
            "into a complete breach scenario. These are detailed in Section 3.",
            s["body"]
        ))

    story.append(Spacer(1, 3*mm))
    return story


def _domain_risk(domain: str, count: int) -> str:
    if domain == "CODE" and count > 10:  return "High exposure — multiple injectable endpoints"
    if domain == "CODE":                  return "Moderate exposure — review injection points"
    if domain == "IAC":                   return "Infrastructure misconfiguration detected"
    if domain == "IAM":                   return "Privilege escalation paths present"
    return "Review required"


# ─── Attack chains ────────────────────────────────────────────────────────────

def _chains(scan: Dict[str, Any], s) -> List:
    chains = scan.get("attack_chains", [])
    if not chains:
        return []

    story = []
    story.append(Paragraph("Attack Chains", s["h2"]))
    story.append(_rule())
    story.append(Paragraph(
        "The following multi-step attack paths were identified. Each chain shows "
        "how separate vulnerabilities combine to enable a complete breach.",
        s["body"]
    ))
    story.append(Spacer(1, 3*mm))

    for i, chain in enumerate(chains):
        risk   = chain.get("risk_score", 0)
        title  = chain.get("title", "Unknown")
        desc   = chain.get("description", "")
        steps  = chain.get("steps", [])
        remed  = chain.get("remediation", "")

        risk_color = RED if risk >= 90 else ORANGE if risk >= 70 else BLUE
        hex_rc = risk_color.hexval() if hasattr(risk_color, "hexval") else "#ff4d6d"

        block = []
        block.append(Paragraph(
            f'<font color="{hex_rc}"><b>Chain {i+1}: {title}</b></font>'
            f'  —  Risk Score: <font color="{hex_rc}"><b>{risk}/100</b></font>',
            s["h3"]
        ))
        block.append(Paragraph(desc, s["body"]))
        block.append(Spacer(1, 2*mm))

        for j, step in enumerate(steps):
            block.append(Paragraph(
                f'<font color="#63ffb4"><b>Step {j+1}:</b></font>  {step}',
                s["body"]
            ))

        if remed:
            block.append(Spacer(1, 2*mm))
            block.append(Paragraph(
                f'<font color="#63ffb4"><b>Priority Fix:</b></font>  {remed}',
                s["body"]
            ))

        # Wrap in a shaded box
        inner_tbl = Table([[block]], colWidths=[PAGE_W - 2*MARGIN - 8*mm])
        inner_tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,-1), HexColor("#0a0e16")),
            ("BOX",           (0,0), (-1,-1), 0.5, risk_color),
            ("LEFTPADDING",   (0,0), (-1,-1), 8),
            ("RIGHTPADDING",  (0,0), (-1,-1), 8),
            ("TOPPADDING",    (0,0), (-1,-1), 8),
            ("BOTTOMPADDING", (0,0), (-1,-1), 8),
        ]))
        story.append(KeepTogether([inner_tbl, Spacer(1, 4*mm)]))

    return story


# ─── Findings table ───────────────────────────────────────────────────────────

def _findings(scan: Dict[str, Any], s) -> List:
    findings = scan.get("findings", [])
    if not findings:
        return []

    story = []
    story.append(Paragraph("Findings", s["h2"]))
    story.append(_rule())
    story.append(Paragraph(
        f"{len(findings)} security findings listed by severity. "
        "Each entry includes the vulnerability type, affected file, CWE reference, and recommended fix.",
        s["body"]
    ))
    story.append(Spacer(1, 3*mm))

    # Header row
    header = [
        Paragraph("<b>SEV</b>",    s["label"]),
        Paragraph("<b>Title</b>",  s["label"]),
        Paragraph("<b>File</b>",   s["label"]),
        Paragraph("<b>CWE</b>",    s["label"]),
    ]
    rows = [header]

    # Group by severity for visual separation
    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    sorted_findings = sorted(
        findings,
        key=lambda f: sev_order.index(f.get("severity", "INFO"))
        if f.get("severity") in sev_order else 99
    )

    row_colors = []
    row_colors.append(("BACKGROUND", (0,0), (-1,0), SURFACE))

    for i, f in enumerate(sorted_findings):
        sev      = f.get("severity", "INFO")
        title    = f.get("title", "—")[:60]
        file_str = (f.get("file") or "—")
        # shorten long paths
        if len(file_str) > 45:
            parts = file_str.replace("\\", "/").split("/")
            file_str = "…/" + "/".join(parts[-2:])
        line     = f.get("line")
        if line:
            file_str += f":{line}"
        cwe      = (f.get("cwe") or "—").split(":")[0]  # just CWE-xxx

        sev_hex = SEV_COLORS.get(sev, MUTED).hexval() \
            if hasattr(SEV_COLORS.get(sev, MUTED), "hexval") else "#a9acb0"

        rows.append([
            Paragraph(f'<font color="{sev_hex}"><b>{sev}</b></font>', s["tag"]),
            Paragraph(title, s["mono_muted"]),
            Paragraph(file_str, s["mono_muted"]),
            Paragraph(cwe, s["mono_muted"]),
        ])
        bg = SEV_BG.get(sev, HexColor("#080b10"))
        row_colors.append(("BACKGROUND", (0, i+1), (-1, i+1), bg))

    col_w = [22*mm, 68*mm, 60*mm, 22*mm]
    tbl = Table(rows, colWidths=col_w, repeatRows=1)

    style_cmds = [
        ("GRID",          (0,0), (-1,-1), 0.3, DARK_RULE),
        ("TOPPADDING",    (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
        ("LEFTPADDING",   (0,0), (-1,-1), 5),
        ("RIGHTPADDING",  (0,0), (-1,-1), 5),
        ("VALIGN",        (0,0), (-1,-1), "TOP"),
    ] + row_colors

    tbl.setStyle(TableStyle(style_cmds))
    story.append(tbl)
    story.append(Spacer(1, 4*mm))
    return story


# ─── Remediation priorities ───────────────────────────────────────────────────

def _remediation(scan: Dict[str, Any], s) -> List:
    findings = scan.get("findings", [])
    fixable  = [f for f in findings if f.get("fix_hint")]
    if not fixable:
        return []

    story = []
    story.append(Paragraph("Remediation Priorities", s["h2"]))
    story.append(_rule())
    story.append(Paragraph(
        "The following fixes are listed in priority order. Addressing these will "
        "have the highest impact on reducing the overall risk score.",
        s["body"]
    ))
    story.append(Spacer(1, 3*mm))

    # Deduplicate by rule_id — one fix per rule type
    seen_rules: set = set()
    unique_fixes = []
    for f in fixable:
        key = f.get("rule_id") or f.get("title")
        if key not in seen_rules:
            seen_rules.add(key)
            unique_fixes.append(f)

    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    unique_fixes.sort(
        key=lambda f: sev_order.index(f.get("severity", "INFO"))
        if f.get("severity") in sev_order else 99
    )

    for i, f in enumerate(unique_fixes[:20]):   # cap at 20
        sev      = f.get("severity", "INFO")
        title    = f.get("title", "")
        fix_hint = f.get("fix_hint", "")
        file_str = f.get("file") or "—"

        sev_hex = SEV_COLORS.get(sev, MUTED).hexval() \
            if hasattr(SEV_COLORS.get(sev, MUTED), "hexval") else "#a9acb0"

        block = [
            Paragraph(
                f'<font color="{sev_hex}"><b>[{sev}]</b></font>  <b>{title}</b>  '
                f'<font color="#555f72">— {file_str}</font>',
                s["h3"]
            ),
            Paragraph(fix_hint, s["body"]),
        ]

        if f.get("fixed_code"):
            code_lines = f["fixed_code"].strip().splitlines()[:6]
            code_str   = "\n".join(code_lines)
            if len(f["fixed_code"].splitlines()) > 6:
                code_str += "\n..."
            block.append(Paragraph(code_str.replace("\n", "<br/>"), s["mono"]))

        inner = Table([[block]], colWidths=[PAGE_W - 2*MARGIN - 8*mm])
        inner.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,-1), HexColor("#080b10")),
            ("BOX",           (0,0), (-1,-1), 0.4, DARK_RULE),
            ("LEFTPADDING",   (0,0), (-1,-1), 8),
            ("RIGHTPADDING",  (0,0), (-1,-1), 8),
            ("TOPPADDING",    (0,0), (-1,-1), 6),
            ("BOTTOMPADDING", (0,0), (-1,-1), 6),
        ]))
        story.append(KeepTogether([inner, Spacer(1, 3*mm)]))

    return story


# ─── Public entry point ───────────────────────────────────────────────────────

def generate_pdf(scan: Dict[str, Any]) -> bytes:
    """
    Generate a PDF report from a scan result dict.
    Returns raw PDF bytes — caller writes to disk or streams as HTTP response.
    """
    buf      = io.BytesIO()
    repo     = scan.get("repo", "Unknown")
    scan_id  = scan.get("scan_id", "unknown")
    total    = scan.get("stats", {}).get("total", 0)

    tmpl = _PageTemplate(repo, scan_id, total)

    doc = SimpleDocTemplate(
        buf,
        pagesize      = A4,
        leftMargin    = MARGIN,
        rightMargin   = MARGIN,
        topMargin     = 18*mm,
        bottomMargin  = 14*mm,
        title         = f"XentinelAI Security Report — {repo}",
        author        = "XentinelAI",
        subject       = "Automated Security Scan",
    )

    s = _styles()

    story = []
    story += _cover(scan, s)
    story += _summary(scan, s)
    story.append(Spacer(1, 4*mm))
    story += _chains(scan, s)
    if scan.get("attack_chains"):
        story.append(PageBreak())
    story += _findings(scan, s)
    story.append(PageBreak())
    story += _remediation(scan, s)

    doc.build(
        story,
        onFirstPage  = tmpl.on_page,
        onLaterPages = tmpl.on_page,
    )

    return buf.getvalue()