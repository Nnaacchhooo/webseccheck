"""WebSecCheck PDF Report Generator - Professional security audit reports."""

import io
import math
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib.colors import HexColor, white, black
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.graphics.shapes import Drawing, Circle, String, Rect, Line
from reportlab.graphics import renderPDF


# Brand colors
BG_DARK = HexColor("#0a0e17")
BG_CARD = HexColor("#111827")
BG_CARD2 = HexColor("#1a2332")
GREEN = HexColor("#00ff88")
CYAN = HexColor("#00d4ff")
RED = HexColor("#ff4444")
ORANGE = HexColor("#ff9900")
YELLOW = HexColor("#ffcc00")
TEXT_WHITE = HexColor("#e2e8f0")
TEXT_GRAY = HexColor("#94a3b8")
TEXT_DIM = HexColor("#64748b")


def get_grade(score: int) -> str:
    if score >= 90: return "A"
    if score >= 80: return "B"
    if score >= 70: return "C"
    if score >= 60: return "D"
    return "F"


def grade_color(grade: str) -> HexColor:
    return {"A": GREEN, "B": CYAN, "C": YELLOW, "D": ORANGE, "F": RED}.get(grade, TEXT_WHITE)


def status_color(status: str) -> HexColor:
    return {"pass": GREEN, "warn": ORANGE, "fail": RED}.get(status, TEXT_WHITE)


def status_icon(status: str) -> str:
    return {"pass": "✓ PASS", "warn": "⚠ WARN", "fail": "✗ FAIL"}.get(status, status.upper())


REMEDIATION_DB = {
    "header_csp": {
        "severity": "High",
        "remediation": "Add a Content-Security-Policy header to your server configuration.",
        "code": "# Nginx\nadd_header Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';\" always;\n\n# Apache\nHeader set Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';\""
    },
    "header_x_frame_options": {
        "severity": "Medium",
        "remediation": "Add X-Frame-Options header to prevent clickjacking.",
        "code": "# Nginx\nadd_header X-Frame-Options \"DENY\" always;\n\n# Apache\nHeader always set X-Frame-Options \"DENY\""
    },
    "header_x_content_type_options": {
        "severity": "Medium",
        "remediation": "Add X-Content-Type-Options to prevent MIME-type sniffing.",
        "code": "# Nginx\nadd_header X-Content-Type-Options \"nosniff\" always;\n\n# Apache\nHeader always set X-Content-Type-Options \"nosniff\""
    },
    "header_referrer_policy": {
        "severity": "Low",
        "remediation": "Set Referrer-Policy to control information leakage.",
        "code": "# Nginx\nadd_header Referrer-Policy \"strict-origin-when-cross-origin\" always;"
    },
    "header_permissions_policy": {
        "severity": "Low",
        "remediation": "Add Permissions-Policy to restrict browser features.",
        "code": "# Nginx\nadd_header Permissions-Policy \"camera=(), microphone=(), geolocation=()\" always;"
    },
    "header_hsts": {
        "severity": "High",
        "remediation": "Enable HSTS to force HTTPS connections.",
        "code": "# Nginx\nadd_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;"
    },
    "ssl_valid": {
        "severity": "Critical",
        "remediation": "Install a valid SSL certificate. Use Let's Encrypt for free certificates.",
        "code": "# Install certbot\nsudo apt install certbot python3-certbot-nginx\nsudo certbot --nginx -d yourdomain.com"
    },
    "ssl_expiry": {
        "severity": "Critical",
        "remediation": "Renew your SSL certificate before expiration.",
        "code": "# Auto-renew with certbot\nsudo certbot renew --dry-run\n# Add cron: 0 0 1 * * certbot renew"
    },
    "cookie_secure": {
        "severity": "High",
        "remediation": "Set the Secure flag on all cookies.",
        "code": "# Python Flask\nresponse.set_cookie('session', value, secure=True, httponly=True, samesite='Lax')\n\n# Express.js\nres.cookie('session', value, { secure: true, httpOnly: true, sameSite: 'lax' });"
    },
    "cookie_httponly": {
        "severity": "High",
        "remediation": "Set HttpOnly flag to prevent JavaScript cookie access.",
        "code": "# See cookie_secure example above - use httponly=True / httpOnly: true"
    },
}

DEFAULT_REMEDIATION = {
    "severity": "Medium",
    "remediation": "Review the check details and apply the recommended configuration changes.",
    "code": "# Consult your web server documentation for specific configuration steps."
}


def _build_styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle("CoverTitle", fontSize=36, textColor=GREEN, fontName="Helvetica-Bold", spaceAfter=12, alignment=1))
    styles.add(ParagraphStyle("CoverSub", fontSize=16, textColor=TEXT_WHITE, fontName="Helvetica", spaceAfter=6, alignment=1))
    styles.add(ParagraphStyle("CoverDim", fontSize=12, textColor=TEXT_GRAY, fontName="Helvetica", spaceAfter=4, alignment=1))
    styles.add(ParagraphStyle("SectionTitle", fontSize=22, textColor=CYAN, fontName="Helvetica-Bold", spaceAfter=12, spaceBefore=20))
    styles.add(ParagraphStyle("SubTitle", fontSize=14, textColor=GREEN, fontName="Helvetica-Bold", spaceAfter=6, spaceBefore=12))
    styles.add(ParagraphStyle("BodyText2", fontSize=10, textColor=TEXT_WHITE, fontName="Helvetica", spaceAfter=6, leading=14))
    styles.add(ParagraphStyle("BodyDim", fontSize=9, textColor=TEXT_GRAY, fontName="Helvetica", spaceAfter=4, leading=12))
    styles.add(ParagraphStyle("Code", fontSize=8, textColor=GREEN, fontName="Courier", spaceAfter=6, leading=11, leftIndent=12, backColor=BG_CARD2))
    styles.add(ParagraphStyle("FooterStyle", fontSize=8, textColor=TEXT_DIM, fontName="Helvetica", alignment=1))
    return styles


def _draw_bg(canvas, doc):
    """Draw dark background on every page."""
    canvas.saveState()
    canvas.setFillColor(BG_DARK)
    canvas.rect(0, 0, letter[0], letter[1], fill=1, stroke=0)
    # Footer
    canvas.setFillColor(TEXT_DIM)
    canvas.setFont("Helvetica", 7)
    canvas.drawCentredString(letter[0] / 2, 20, f"WebSecCheck Security Report — Confidential — Page {canvas.getPageNumber()}")
    canvas.restoreState()


def _score_gauge(score: int, grade: str) -> Drawing:
    """Create a circular score gauge."""
    d = Drawing(200, 200)
    cx, cy, r = 100, 100, 80

    # Background circle
    d.add(Circle(cx, cy, r, fillColor=BG_CARD, strokeColor=TEXT_DIM, strokeWidth=2))

    # Arc segments (simulate with colored wedges)
    color = grade_color(grade)
    inner_r = 65
    # Draw progress arc as series of small rectangles around the circle
    segments = int(score * 3.6)  # 360 degrees max
    for deg in range(0, segments, 3):
        rad = math.radians(deg - 90)
        x1 = cx + inner_r * math.cos(rad)
        y1 = cy + inner_r * math.sin(rad)
        x2 = cx + r * math.cos(rad)
        y2 = cy + r * math.sin(rad)
        d.add(Line(x1, y1, x2, y2, strokeColor=color, strokeWidth=3))

    # Inner circle
    d.add(Circle(cx, cy, inner_r - 5, fillColor=BG_DARK, strokeWidth=0))

    # Score text
    d.add(String(cx, cy + 10, str(score), fontSize=36, fillColor=color, fontName="Helvetica-Bold", textAnchor="middle"))
    d.add(String(cx, cy - 12, f"Grade: {grade}", fontSize=14, fillColor=TEXT_WHITE, fontName="Helvetica", textAnchor="middle"))
    d.add(String(cx, cy - 28, "out of 100", fontSize=9, fillColor=TEXT_GRAY, fontName="Helvetica", textAnchor="middle"))

    return d


def _executive_summary(score: int, grade: str, hostname: str, checks: list, passed: int, warnings: int, failed: int) -> str:
    total = len(checks)

    if grade == "A":
        posture = f"{hostname} demonstrates an excellent security posture. The vast majority of security controls are properly configured, and the site follows modern web security best practices."
    elif grade == "B":
        posture = f"{hostname} shows a good security posture with most security controls in place. There are a few areas that could be improved to achieve a top-tier security configuration."
    elif grade == "C":
        posture = f"{hostname} has a moderate security posture. While some basic protections are in place, several important security headers and configurations are missing, leaving the site exposed to common attack vectors."
    elif grade == "D":
        posture = f"{hostname} has a below-average security posture. Multiple critical security controls are missing, which significantly increases the attack surface and risk of exploitation."
    else:
        posture = f"{hostname} has a poor security posture requiring immediate attention. The majority of security controls are missing or misconfigured, leaving the site highly vulnerable to common web attacks."

    stats = f"Our scan performed {total} security checks across multiple categories. Results: {passed} passed, {warnings} warnings, and {failed} failures. The overall security score is {score}/100 (Grade {grade})."

    recommendation = "We recommend addressing the failed checks in order of severity, starting with Critical and High severity items. The Priority Action Plan section below provides a step-by-step remediation roadmap."

    return f"{posture}\n\n{stats}\n\n{recommendation}"


def generate_pdf(scan_data: dict) -> bytes:
    """Generate a professional PDF report from scan results. Returns PDF bytes."""
    buf = io.BytesIO()
    styles = _build_styles()

    doc = SimpleDocTemplate(buf, pagesize=letter, topMargin=0.5*inch, bottomMargin=0.5*inch,
                            leftMargin=0.75*inch, rightMargin=0.75*inch)
    story = []

    url = scan_data["url"]
    hostname = scan_data["hostname"]
    score = scan_data["score"]
    grade = scan_data["grade"]
    checks = scan_data["checks"]
    passed = scan_data["passed"]
    warnings = scan_data["warnings"]
    failed = scan_data["failed"]
    scan_time = scan_data.get("scan_time_seconds", 0)
    now = datetime.utcnow().strftime("%B %d, %Y at %H:%M UTC")

    # ── Cover Page ──
    story.append(Spacer(1, 1.5*inch))
    story.append(Paragraph("🛡 WebSecCheck", styles["CoverTitle"]))
    story.append(Spacer(1, 8))
    story.append(Paragraph("Security Audit Report", styles["CoverSub"]))
    story.append(Spacer(1, 0.5*inch))
    story.append(Paragraph(f"Target: {hostname}", styles["CoverSub"]))
    story.append(Paragraph(f"URL: {url}", styles["CoverDim"]))
    story.append(Paragraph(f"Scan Date: {now}", styles["CoverDim"]))
    story.append(Paragraph(f"Scan Duration: {scan_time}s", styles["CoverDim"]))
    story.append(Spacer(1, 0.5*inch))

    # Score gauge on cover
    gauge = _score_gauge(score, grade)
    story.append(gauge)

    story.append(Spacer(1, 0.3*inch))
    color_hex = grade_color(grade).hexval() if hasattr(grade_color(grade), 'hexval') else "#00ff88"
    story.append(Paragraph(f'<font color="{color_hex}" size="28"><b>Grade: {grade}</b></font>', styles["CoverSub"]))
    story.append(Paragraph(f"Score: {score}/100 — {passed} passed · {warnings} warnings · {failed} failed", styles["CoverDim"]))

    story.append(PageBreak())

    # ── Executive Summary ──
    story.append(Paragraph("Executive Summary", styles["SectionTitle"]))
    summary = _executive_summary(score, grade, hostname, checks, passed, warnings, failed)
    for para in summary.split("\n\n"):
        story.append(Paragraph(para, styles["BodyText2"]))
        story.append(Spacer(1, 6))

    story.append(Spacer(1, 0.3*inch))

    # ── Category Breakdown ──
    story.append(Paragraph("Category Breakdown", styles["SectionTitle"]))

    categories = {}
    for c in checks:
        cat = c.get("category", "Other")
        if cat not in categories:
            categories[cat] = {"pass": 0, "warn": 0, "fail": 0, "total": 0}
        categories[cat][c["status"]] = categories[cat].get(c["status"], 0) + 1
        categories[cat]["total"] += 1

    table_data = [["Category", "Checks", "Passed", "Warnings", "Failed", "Score"]]
    for cat, counts in sorted(categories.items()):
        cat_score = round((counts["pass"] * 100 + counts["warn"] * 50) / max(counts["total"], 1))
        table_data.append([cat, str(counts["total"]), str(counts["pass"]), str(counts["warn"]), str(counts["fail"]), f"{cat_score}%"])

    t = Table(table_data, colWidths=[2*inch, 0.7*inch, 0.7*inch, 0.85*inch, 0.7*inch, 0.7*inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), BG_CARD2),
        ("TEXTCOLOR", (0, 0), (-1, 0), CYAN),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("TEXTCOLOR", (0, 1), (-1, -1), TEXT_WHITE),
        ("BACKGROUND", (0, 1), (-1, -1), BG_CARD),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [BG_CARD, BG_CARD2]),
        ("GRID", (0, 0), (-1, -1), 0.5, TEXT_DIM),
        ("ALIGN", (1, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(t)

    story.append(PageBreak())

    # ── Detailed Findings ──
    story.append(Paragraph("Detailed Findings", styles["SectionTitle"]))

    for check in checks:
        cid = check.get("id", "")
        status = check.get("status", "unknown")
        name = check.get("name", "Unknown Check")
        desc = check.get("description", "")
        category = check.get("category", "")

        rem_info = REMEDIATION_DB.get(cid, DEFAULT_REMEDIATION)
        severity = rem_info["severity"]
        s_color = status_color(status)
        s_hex = "#00ff88" if status == "pass" else ("#ff9900" if status == "warn" else "#ff4444")

        story.append(Paragraph(
            f'<font color="{s_hex}"><b>{status_icon(status)}</b></font>  '
            f'<b>{name}</b>  '
            f'<font color="#94a3b8" size="8">[{category} · Severity: {severity}]</font>',
            styles["BodyText2"]
        ))
        story.append(Paragraph(desc, styles["BodyDim"]))

        if status != "pass":
            story.append(Paragraph(f'<b>Remediation:</b> {rem_info["remediation"]}', styles["BodyDim"]))
            code_lines = rem_info["code"].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br/>")
            story.append(Paragraph(code_lines, styles["Code"]))

        story.append(Spacer(1, 8))

    story.append(PageBreak())

    # ── Priority Action Plan ──
    story.append(Paragraph("Priority Action Plan", styles["SectionTitle"]))
    story.append(Paragraph("Address these items in order of priority to improve your security score:", styles["BodyText2"]))
    story.append(Spacer(1, 8))

    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    failed_checks = [c for c in checks if c["status"] in ("fail", "warn")]
    failed_checks.sort(key=lambda c: severity_order.get(REMEDIATION_DB.get(c.get("id", ""), DEFAULT_REMEDIATION)["severity"], 5))

    for i, check in enumerate(failed_checks, 1):
        rem = REMEDIATION_DB.get(check.get("id", ""), DEFAULT_REMEDIATION)
        sev = rem["severity"]
        sev_color = {"Critical": "#ff4444", "High": "#ff9900", "Medium": "#ffcc00", "Low": "#94a3b8"}.get(sev, "#94a3b8")
        story.append(Paragraph(
            f'<b>{i}.</b> <font color="{sev_color}">[{sev}]</font> {check["name"]} — {rem["remediation"]}',
            styles["BodyText2"]
        ))

    if not failed_checks:
        story.append(Paragraph("✓ No critical issues found. Maintain your current security configuration.", styles["BodyText2"]))

    story.append(PageBreak())

    # ── About WebSecCheck ──
    story.append(Paragraph("About WebSecCheck", styles["SectionTitle"]))
    story.append(Paragraph(
        "WebSecCheck is an automated passive security scanner that analyzes websites for common security "
        "misconfigurations and vulnerabilities without performing any intrusive testing. Our scans check "
        "SSL/TLS configuration, HTTP security headers, DNS records, cookie security, server information "
        "exposure, and CMS detection.",
        styles["BodyText2"]
    ))
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        "All checks are non-intrusive and read-only — we never send malicious payloads or attempt to exploit "
        "vulnerabilities. This report provides actionable recommendations with code examples to help you "
        "improve your website's security posture.",
        styles["BodyText2"]
    ))
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        "For questions or custom enterprise assessments, visit webseccheck.com or contact our security team.",
        styles["BodyText2"]
    ))
    story.append(Spacer(1, 0.5*inch))
    story.append(Paragraph("— WebSecCheck Security Team", styles["CoverDim"]))

    # Build PDF
    doc.build(story, onFirstPage=_draw_bg, onLaterPages=_draw_bg)
    return buf.getvalue()
