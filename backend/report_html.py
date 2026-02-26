"""Dynamic HTML report generator — same design as the static demo but populated with real scan data."""

import html
from datetime import datetime
import secrets

# Severity mapping for check IDs
SEVERITY_MAP = {
    "header_csp": "critical",
    "header_x_frame_options": "critical", 
    "header_hsts": "critical",
    "header_x_content_type_options": "medium",
    "header_referrer_policy": "high",
    "header_permissions_policy": "medium",
    "ssl_valid": "critical",
    "ssl_expiry": "critical",
    "cookie_secure": "high",
    "cookie_httponly": "high",
    "dns_dmarc": "high",
    "dns_dkim": "medium",
    "dns_spf": "medium",
    "server_version": "low",
    "server_powered_by": "low",
    "cms_version": "low",
}

REMEDIATION_MAP = {
    "header_csp": {
        "description": "The Content-Security-Policy header is not set. CSP is the most powerful browser-side defense against XSS attacks.",
        "impact": ["Attackers can inject malicious scripts", "No protection against inline script execution", "Third-party resources loaded without restriction"],
        "remediation_title": "Add CSP Header",
        "remediation_text": "Add a Content-Security-Policy header via your web server or CDN.",
        "code": """Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self' https:; frame-ancestors 'none';""",
    },
    "header_x_frame_options": {
        "description": "X-Frame-Options header is missing. This prevents clickjacking attacks.",
        "impact": ["Clickjacking attacks possible", "Users tricked into clicking hidden elements"],
        "remediation_title": "Add X-Frame-Options",
        "remediation_text": "Set X-Frame-Options to DENY or SAMEORIGIN.",
        "code": "X-Frame-Options: DENY",
    },
    "header_hsts": {
        "description": "HSTS not configured. Forces browsers to always use HTTPS.",
        "impact": ["Vulnerable to SSL-stripping attacks", "First-visit HTTP interception possible"],
        "remediation_title": "Enable HSTS",
        "remediation_text": "Add Strict-Transport-Security header.",
        "code": "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "header_x_content_type_options": {
        "description": "X-Content-Type-Options header missing. Prevents MIME-type sniffing.",
        "impact": ["MIME confusion attacks possible", "Uploaded files could execute as scripts"],
        "remediation_title": "Add X-Content-Type-Options",
        "remediation_text": "Set nosniff to prevent MIME sniffing.",
        "code": "X-Content-Type-Options: nosniff",
    },
    "header_referrer_policy": {
        "description": "Referrer-Policy not set. Controls URL information sent to third parties.",
        "impact": ["Sensitive URL data leaked to third parties", "Internal URL structure exposed"],
        "remediation_title": "Add Referrer-Policy",
        "remediation_text": "Set strict-origin-when-cross-origin.",
        "code": "Referrer-Policy: strict-origin-when-cross-origin",
    },
    "header_permissions_policy": {
        "description": "Permissions-Policy header missing. Controls browser feature access.",
        "impact": ["Embedded content could access camera/microphone", "Third-party scripts use powerful APIs"],
        "remediation_title": "Add Permissions-Policy",
        "remediation_text": "Restrict unnecessary browser features.",
        "code": "Permissions-Policy: camera=(), microphone=(), geolocation=()",
    },
}

DEFAULT_REMEDIATION = {
    "description": "Review the check details and apply recommended fixes.",
    "impact": ["Potential security risk identified"],
    "remediation_title": "Fix This Issue",
    "remediation_text": "Consult your web server documentation for configuration steps.",
    "code": "# See documentation for your specific web server",
}


def _esc(text: str) -> str:
    return html.escape(str(text))


def _grade_color(grade: str) -> str:
    return {"A": "#00FF41", "B": "#00cc33", "C": "#ffd600", "D": "#ff9800", "F": "#ff4444"}.get(grade, "#fff")


def _status_class(status: str) -> str:
    return {"pass": "pass", "warn": "warn", "fail": "fail"}.get(status, "fail")


def _severity_label(check_id: str) -> str:
    return SEVERITY_MAP.get(check_id, "medium")


def generate_report_html(scan_data: dict) -> str:
    """Generate a full HTML report from scan data."""
    hostname = _esc(scan_data["hostname"])
    url = _esc(scan_data["url"])
    score = scan_data["score"]
    grade = scan_data["grade"]
    checks = scan_data["checks"]
    passed = scan_data["passed"]
    warnings = scan_data["warnings"]
    failed = scan_data["failed"]
    scan_time = scan_data.get("scan_time_seconds", 0)
    
    now = datetime.utcnow().strftime("%B %d, %Y — %H:%M UTC")
    report_id = f"WSC-{datetime.utcnow().strftime('%Y-%m%d')}-{secrets.token_hex(2).upper()}"
    grade_col = _grade_color(grade)
    
    # Gauge offset calculation (691.15 is circumference for r=110)
    circumference = 691.15
    gauge_offset = circumference - (circumference * score / 100)
    
    # Build executive summary
    if grade == "A":
        summary_text = f"{hostname} demonstrates an excellent security posture with most controls properly configured."
        risk_level = "LOW"
        risk_color = "#00FF41"
    elif grade == "B":
        summary_text = f"{hostname} shows a good security posture with minor areas for improvement."
        risk_level = "MODERATE"
        risk_color = "#00cc33"
    elif grade == "C":
        summary_text = f"{hostname} has a moderate security posture. Several important headers and configurations are missing."
        risk_level = "MODERATE"
        risk_color = "#ff9800"
    elif grade == "D":
        summary_text = f"{hostname} has significant security gaps that need immediate attention."
        risk_level = "HIGH"
        risk_color = "#ff4444"
    else:
        summary_text = f"{hostname} has a poor security posture requiring urgent remediation."
        risk_level = "CRITICAL"
        risk_color = "#ff1744"
    
    critical_count = sum(1 for c in checks if c["status"] == "fail" and _severity_label(c.get("id", "")) in ("critical", "high"))
    
    # Build categories
    categories = {}
    for c in checks:
        cat = c.get("category", "Other")
        if cat not in categories:
            categories[cat] = {"checks": [], "pass": 0, "warn": 0, "fail": 0}
        categories[cat]["checks"].append(c)
        categories[cat][c["status"]] = categories[cat].get(c["status"], 0) + 1
    
    cat_icons = {"SSL/TLS": "🔒", "HTTP Headers": "🛡️", "DNS": "📧", "Server Exposure": "⚙️", 
                 "Cookies": "🍪", "CMS Detection": "🔍", "Mixed Content": "🔗", "Redirects": "↗️"}
    
    # Category cards HTML
    cat_cards = ""
    for cat, data in categories.items():
        total = len(data["checks"])
        cat_score = round((data["pass"] * 100 + data["warn"] * 50) / max(total, 1))
        score_class = "good" if cat_score >= 70 else ("mid" if cat_score >= 40 else "bad")
        bar_color = "#00FF41" if cat_score >= 70 else ("#ff9800" if cat_score >= 40 else "#ff4444")
        icon = cat_icons.get(cat, "📋")
        
        checks_html = ""
        for c in data["checks"]:
            status = c["status"]
            icon_char = "✓" if status == "pass" else ("!" if status == "warn" else "✗")
            checks_html += f'<div class="cat-check"><div class="icon {status}">{icon_char}</div><span>{_esc(c["name"])} — {_esc(c["description"][:80])}</span></div>\n'
        
        cat_cards += f"""
  <div class="cat-card">
    <div class="cat-card-header">
      <div class="cat-card-title">{icon} {_esc(cat)}</div>
      <div class="cat-score {score_class}">{cat_score}%</div>
    </div>
    <div class="cat-bar"><div class="cat-bar-fill" style="width:{cat_score}%;background:{bar_color}"></div></div>
    <div class="cat-checks">{checks_html}</div>
  </div>"""
    
    # Findings HTML
    findings_html = ""
    for i, check in enumerate(checks):
        cid = check.get("id", "")
        status = check["status"]
        severity = _severity_label(cid)
        rem = REMEDIATION_MAP.get(cid, DEFAULT_REMEDIATION)
        open_class = " open" if i == 0 else ""
        
        status_label = "PASS" if status == "pass" else ("WARN" if status == "warn" else "FAIL")
        sev_class = "pass-badge" if status == "pass" else severity
        sev_label = "Pass" if status == "pass" else severity.capitalize()
        
        body_html = ""
        if status != "pass":
            impact_items = "".join(f"<li>{_esc(imp)}</li>" for imp in rem["impact"])
            body_html = f"""
  <div class="finding-body">
    <div class="finding-grid">
      <div>
        <div class="finding-section">
          <h4>Description</h4>
          <p>{_esc(rem['description'])}</p>
        </div>
        <div class="finding-section">
          <h4>Impact</h4>
          <ul>{impact_items}</ul>
        </div>
      </div>
      <div>
        <div class="finding-section">
          <h4>{_esc(rem['remediation_title'])}</h4>
          <p>{_esc(rem['remediation_text'])}</p>
          <pre>{_esc(rem['code'])}</pre>
        </div>
      </div>
    </div>
  </div>"""
        else:
            body_html = f"""
  <div class="finding-body">
    <div class="finding-section">
      <h4>Details</h4>
      <p>✅ {_esc(check['description'])}</p>
    </div>
  </div>"""
        
        findings_html += f"""
<div class="finding{open_class}">
  <div class="finding-header" onclick="this.parentElement.classList.toggle('open')">
    <span class="severity-badge {sev_class}">{sev_label}</span>
    <span class="finding-name">{_esc(check['name'])}</span>
    <span class="finding-status {status}">{status_label}</span>
    <span class="chevron">›</span>
  </div>
  {body_html}
</div>"""
    
    # Action plan rows
    action_rows = ""
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    failed_checks = [c for c in checks if c["status"] in ("fail", "warn")]
    failed_checks.sort(key=lambda c: severity_order.get(_severity_label(c.get("id", "")), 5))
    
    effort_map = {"critical": "5-15 min", "high": "5 min", "medium": "5-10 min", "low": "1-2 min"}
    
    for i, check in enumerate(failed_checks, 1):
        sev = _severity_label(check.get("id", ""))
        sev_color = {"critical": "#ff1744", "high": "#ff5252", "medium": "#ff9800", "low": "#ffd600"}.get(sev, "#888")
        rem = REMEDIATION_MAP.get(check.get("id", ""), DEFAULT_REMEDIATION)
        effort = effort_map.get(sev, "5 min")
        
        action_rows += f"""
  <tr>
    <td><div class="priority-num" style="background:{sev_color}">{i}</div></td>
    <td><strong style="color:#fff">{_esc(check['name'])}</strong><br><span style="color:var(--text2);font-size:13px">{_esc(rem['remediation_text'][:80])}</span></td>
    <td><span class="severity-badge {sev}" style="font-size:10px">{sev.capitalize()}</span></td>
    <td><span class="effort-tag">{effort}</span></td>
    <td style="color:var(--text2)">{_esc(rem['description'][:60])}</td>
  </tr>"""
    
    if not action_rows:
        action_rows = '<tr><td colspan="5" style="text-align:center;color:#00FF41;padding:24px;">✓ No critical issues found!</td></tr>'

    # Full HTML template (uses same CSS as static demo)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WebSecCheck Security Report — {hostname}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
:root{{--bg:#0a0a0a;--bg2:#111;--bg3:#1a1a1a;--bg4:#222;--green:#00FF41;--green2:#00cc33;--red:#ff4444;--orange:#ff9800;--yellow:#ffd600;--blue:#4fc3f7;--gray:#888;--gray2:#555;--text:#e0e0e0;--text2:#aaa;--border:#2a2a2a;--critical:#ff1744;--high:#ff5252;--medium:#ff9800;--low:#ffd600;--info:#4fc3f7;--pass:#00FF41}}
body{{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,-apple-system,sans-serif;line-height:1.6;min-height:100vh}}
a{{color:var(--green)}}
.container{{max-width:1100px;margin:0 auto;padding:0 24px}}
.report-header{{background:linear-gradient(135deg,#0a0a0a 0%,#0f1a0f 50%,#0a0a0a 100%);border-bottom:1px solid var(--border);padding:40px 0}}
.header-top{{display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:20px}}
.brand{{display:flex;align-items:center;gap:12px}}
.brand-icon{{width:48px;height:48px;border:2px solid var(--green);border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:24px;background:rgba(0,255,65,.05)}}
.brand h1{{font-size:24px;font-weight:700;color:#fff;letter-spacing:-.5px}}
.brand h1 span{{color:var(--green)}}
.report-badge{{background:linear-gradient(135deg,var(--green),var(--green2));color:#000;padding:6px 16px;border-radius:20px;font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:1px}}
.report-meta{{margin-top:24px;display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px}}
.meta-item{{background:var(--bg2);border:1px solid var(--border);border-radius:8px;padding:14px 18px}}
.meta-label{{font-size:11px;text-transform:uppercase;letter-spacing:1px;color:var(--gray);margin-bottom:4px}}
.meta-value{{font-size:15px;color:#fff;font-weight:600;word-break:break-all}}
.meta-value.domain{{color:var(--green)}}
.report-nav{{background:var(--bg2);border-bottom:1px solid var(--border);padding:12px 0;position:sticky;top:0;z-index:100;backdrop-filter:blur(10px)}}
.nav-inner{{display:flex;gap:4px;overflow-x:auto;padding:0 24px}}
.nav-inner a{{color:var(--text2);text-decoration:none;font-size:13px;padding:6px 14px;border-radius:6px;white-space:nowrap;transition:.2s}}
.nav-inner a:hover{{color:#fff;background:var(--bg3)}}
section{{padding:48px 0;border-bottom:1px solid var(--border)}}
section:last-of-type{{border-bottom:none}}
.section-header{{margin-bottom:32px}}
.section-num{{font-size:12px;text-transform:uppercase;letter-spacing:2px;color:var(--green);font-weight:700;margin-bottom:6px}}
.section-title{{font-size:28px;font-weight:700;color:#fff}}
.section-subtitle{{color:var(--text2);margin-top:6px;font-size:15px}}
.score-area{{display:flex;align-items:center;gap:60px;flex-wrap:wrap;justify-content:center}}
.gauge-wrap{{position:relative;width:260px;height:260px;flex-shrink:0}}
.gauge-svg{{width:100%;height:100%;transform:rotate(-90deg)}}
.gauge-bg{{fill:none;stroke:var(--bg4);stroke-width:18}}
.gauge-fill{{fill:none;stroke:{grade_col};stroke-width:18;stroke-linecap:round;stroke-dasharray:{circumference};stroke-dashoffset:{gauge_offset}}}
.gauge-center{{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);text-align:center}}
.gauge-score{{font-size:72px;font-weight:800;color:#fff;line-height:1}}
.gauge-max{{font-size:18px;color:var(--gray);margin-top:2px}}
.gauge-grade{{display:inline-block;margin-top:8px;background:{grade_col};color:#000;font-size:20px;font-weight:800;padding:4px 18px;border-radius:6px;letter-spacing:2px}}
.score-summary{{flex:1;min-width:280px}}
.score-summary h3{{font-size:20px;color:#fff;margin-bottom:12px}}
.score-summary p{{color:var(--text2);margin-bottom:16px;font-size:15px;line-height:1.7}}
.stat-row{{display:flex;gap:16px;flex-wrap:wrap;margin-top:20px}}
.stat-box{{background:var(--bg3);border:1px solid var(--border);border-radius:10px;padding:16px 20px;flex:1;min-width:100px;text-align:center}}
.stat-num{{font-size:28px;font-weight:800}}
.stat-num.pass{{color:var(--pass)}}
.stat-num.fail{{color:var(--red)}}
.stat-num.warn{{color:var(--orange)}}
.stat-label{{font-size:11px;text-transform:uppercase;letter-spacing:1px;color:var(--gray);margin-top:4px}}
.cat-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:16px}}
.cat-card{{background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:24px;transition:.2s}}
.cat-card:hover{{border-color:var(--gray2)}}
.cat-card-header{{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px}}
.cat-card-title{{font-size:16px;font-weight:700;color:#fff}}
.cat-score{{font-size:14px;font-weight:700;padding:4px 12px;border-radius:6px}}
.cat-score.good{{background:rgba(0,255,65,.1);color:var(--green)}}
.cat-score.bad{{background:rgba(255,68,68,.1);color:var(--red)}}
.cat-score.mid{{background:rgba(255,152,0,.1);color:var(--orange)}}
.cat-bar{{height:6px;background:var(--bg4);border-radius:3px;overflow:hidden;margin-bottom:16px}}
.cat-bar-fill{{height:100%;border-radius:3px}}
.cat-checks{{display:flex;flex-direction:column;gap:8px}}
.cat-check{{display:flex;align-items:center;gap:10px;font-size:13px}}
.cat-check .icon{{width:20px;height:20px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:11px;flex-shrink:0;font-weight:700}}
.cat-check .icon.pass{{background:rgba(0,255,65,.15);color:var(--green)}}
.cat-check .icon.fail{{background:rgba(255,68,68,.15);color:var(--red)}}
.cat-check .icon.warn{{background:rgba(255,152,0,.15);color:var(--orange)}}
.finding{{background:var(--bg2);border:1px solid var(--border);border-radius:12px;margin-bottom:16px;overflow:hidden}}
.finding-header{{padding:20px 24px;display:flex;align-items:center;gap:16px;cursor:pointer;flex-wrap:wrap}}
.severity-badge{{padding:4px 12px;border-radius:6px;font-size:11px;font-weight:800;text-transform:uppercase;letter-spacing:1px;flex-shrink:0}}
.severity-badge.critical{{background:rgba(255,23,68,.15);color:var(--critical);border:1px solid rgba(255,23,68,.3)}}
.severity-badge.high{{background:rgba(255,82,82,.15);color:var(--high);border:1px solid rgba(255,82,82,.3)}}
.severity-badge.medium{{background:rgba(255,152,0,.15);color:var(--medium);border:1px solid rgba(255,152,0,.3)}}
.severity-badge.low{{background:rgba(255,214,0,.15);color:var(--low);border:1px solid rgba(255,214,0,.3)}}
.severity-badge.pass-badge{{background:rgba(0,255,65,.1);color:var(--pass);border:1px solid rgba(0,255,65,.3)}}
.finding-name{{font-size:16px;font-weight:700;color:#fff;flex:1}}
.finding-status{{font-size:13px;font-weight:700;padding:4px 12px;border-radius:6px}}
.finding-status.pass{{background:rgba(0,255,65,.1);color:var(--green)}}
.finding-status.fail{{background:rgba(255,68,68,.1);color:var(--red)}}
.finding-status.warn{{background:rgba(255,152,0,.1);color:var(--orange)}}
.finding-body{{padding:0 24px 24px;display:none}}
.finding.open .finding-body{{display:block}}
.finding-grid{{display:grid;grid-template-columns:1fr 1fr;gap:20px}}
@media(max-width:700px){{.finding-grid{{grid-template-columns:1fr}}}}
.finding-section{{margin-bottom:16px}}
.finding-section h4{{font-size:12px;text-transform:uppercase;letter-spacing:1px;color:var(--green);margin-bottom:8px;font-weight:700}}
.finding-section p,.finding-section li{{color:var(--text2);font-size:14px;line-height:1.7}}
.finding-section ul{{padding-left:18px}}
code{{background:var(--bg4);color:var(--green);padding:2px 6px;border-radius:4px;font-size:13px;font-family:'SF Mono','Fira Code',monospace}}
pre{{background:#0d1117;border:1px solid var(--border);border-radius:8px;padding:16px;overflow-x:auto;margin:8px 0;font-size:13px;line-height:1.6;color:var(--green);font-family:'SF Mono','Fira Code',monospace}}
.chevron{{color:var(--gray);transition:.2s;font-size:18px;flex-shrink:0}}
.finding.open .chevron{{transform:rotate(90deg)}}
.action-table{{width:100%;border-collapse:collapse}}
.action-table th{{text-align:left;font-size:11px;text-transform:uppercase;letter-spacing:1px;color:var(--gray);padding:12px 16px;border-bottom:1px solid var(--border)}}
.action-table td{{padding:14px 16px;border-bottom:1px solid var(--border);font-size:14px;vertical-align:top}}
.action-table tr:hover td{{background:var(--bg3)}}
.priority-num{{width:32px;height:32px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:14px;color:#000}}
.effort-tag{{font-size:12px;padding:3px 10px;border-radius:4px;background:var(--bg4);color:var(--text2)}}
.cta-box{{background:linear-gradient(135deg,rgba(0,255,65,.05),rgba(0,255,65,.02));border:1px solid rgba(0,255,65,.2);border-radius:12px;padding:32px;text-align:center;margin-top:32px}}
.cta-box h3{{color:#fff;font-size:20px;margin-bottom:8px}}
.cta-box p{{color:var(--text2);margin-bottom:20px}}
.cta-btn{{display:inline-block;background:var(--green);color:#000;padding:12px 32px;border-radius:8px;font-weight:700;text-decoration:none;font-size:15px;transition:.2s}}
.cta-btn:hover{{background:#00e639;transform:translateY(-1px)}}
.report-footer{{background:var(--bg2);border-top:1px solid var(--border);padding:32px 0;text-align:center}}
.footer-brand{{font-size:18px;font-weight:700;color:#fff;margin-bottom:4px}}
.footer-brand span{{color:var(--green)}}
.footer-text{{color:var(--gray);font-size:13px}}
.footer-disclaimer{{color:var(--gray2);font-size:12px;margin-top:16px;max-width:700px;margin-left:auto;margin-right:auto;line-height:1.6}}
.watermark{{position:fixed;bottom:20px;right:20px;background:var(--bg3);border:1px solid var(--border);border-radius:8px;padding:8px 14px;font-size:11px;color:var(--gray);z-index:50;opacity:.7}}
.watermark span{{color:var(--green)}}
@media print{{body{{background:#fff;color:#222}}.report-nav,.watermark,.cta-box{{display:none}}.finding-body{{display:block!important}}pre{{background:#f5f5f5;color:#222;border-color:#ddd}}.section-title,.finding-name{{color:#111}}}}
</style>
</head>
<body>

<header class="report-header">
<div class="container">
  <div class="header-top">
    <div class="brand">
      <div class="brand-icon">🛡️</div>
      <div>
        <h1>Web<span>Sec</span>Check</h1>
        <div style="font-size:12px;color:var(--gray);letter-spacing:1px">SECURITY ASSESSMENT REPORT</div>
      </div>
    </div>
    <div class="report-badge">Full Security Audit</div>
  </div>
  <div class="report-meta">
    <div class="meta-item">
      <div class="meta-label">Target Domain</div>
      <div class="meta-value domain">{hostname}</div>
    </div>
    <div class="meta-item">
      <div class="meta-label">Scan Date</div>
      <div class="meta-value">{now}</div>
    </div>
    <div class="meta-item">
      <div class="meta-label">Report ID</div>
      <div class="meta-value" style="font-family:monospace;font-size:13px">{report_id}</div>
    </div>
    <div class="meta-item">
      <div class="meta-label">Overall Grade</div>
      <div class="meta-value" style="color:{grade_col};font-size:22px">{grade} — {score} / 100</div>
    </div>
  </div>
</div>
</header>

<nav class="report-nav">
<div class="nav-inner container">
  <a href="#executive-summary">Executive Summary</a>
  <a href="#score">Overall Score</a>
  <a href="#categories">Categories</a>
  <a href="#findings">Detailed Findings</a>
  <a href="#action-plan">Action Plan</a>
</div>
</nav>

<main class="container">

<section id="executive-summary">
<div class="section-header">
  <div class="section-num">01 — Executive Summary</div>
  <h2 class="section-title">Security Posture Overview</h2>
</div>
<div style="background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:28px;border-left:4px solid {grade_col}">
  <p style="font-size:16px;color:#fff;font-weight:600;margin-bottom:12px">{summary_text}</p>
  <p style="color:var(--text2);font-size:15px;line-height:1.8">Our scan performed <strong style="color:#fff">{len(checks)} security checks</strong> across multiple categories. Results: <strong style="color:#00FF41">{passed} passed</strong>, <strong style="color:#ff9800">{warnings} warnings</strong>, and <strong style="color:#ff4444">{failed} failed</strong>. Scan completed in {scan_time:.2f}s.</p>
</div>
<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;margin-top:20px">
  <div style="background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:20px">
    <div style="font-size:13px;color:var(--gray);margin-bottom:6px">Checks Performed</div>
    <div style="font-size:32px;font-weight:800;color:#fff">{len(checks)}</div>
  </div>
  <div style="background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:20px">
    <div style="font-size:13px;color:var(--gray);margin-bottom:6px">Critical Issues</div>
    <div style="font-size:32px;font-weight:800;color:var(--red)">{critical_count}</div>
  </div>
  <div style="background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:20px">
    <div style="font-size:13px;color:var(--gray);margin-bottom:6px">Risk Exposure</div>
    <div style="font-size:32px;font-weight:800;color:{risk_color}">{risk_level}</div>
  </div>
</div>
</section>

<section id="score">
<div class="section-header">
  <div class="section-num">02 — Overall Score</div>
  <h2 class="section-title">Security Score</h2>
</div>
<div class="score-area">
  <div class="gauge-wrap">
    <svg class="gauge-svg" viewBox="0 0 240 240">
      <circle class="gauge-bg" cx="120" cy="120" r="110"/>
      <circle class="gauge-fill" cx="120" cy="120" r="110"/>
    </svg>
    <div class="gauge-center">
      <div class="gauge-score">{score}</div>
      <div class="gauge-max">out of 100</div>
      <div class="gauge-grade">{grade}</div>
    </div>
  </div>
  <div class="score-summary">
    <h3>Score Breakdown</h3>
    <p>A score of {score} places your site in the <strong style="color:{grade_col}">Grade {grade}</strong> tier.</p>
    <div class="stat-row">
      <div class="stat-box"><div class="stat-num pass">{passed}</div><div class="stat-label">Passed</div></div>
      <div class="stat-box"><div class="stat-num fail">{failed}</div><div class="stat-label">Failed</div></div>
      <div class="stat-box"><div class="stat-num warn">{warnings}</div><div class="stat-label">Warnings</div></div>
    </div>
  </div>
</div>
</section>

<section id="categories">
<div class="section-header">
  <div class="section-num">03 — Category Breakdown</div>
  <h2 class="section-title">Results by Category</h2>
</div>
<div class="cat-grid">{cat_cards}</div>
</section>

<section id="findings">
<div class="section-header">
  <div class="section-num">04 — Detailed Findings</div>
  <h2 class="section-title">Complete Analysis</h2>
  <p class="section-subtitle">Click any finding to expand details and remediation</p>
</div>
{findings_html}
</section>

<section id="action-plan">
<div class="section-header">
  <div class="section-num">05 — Priority Action Plan</div>
  <h2 class="section-title">Recommended Fix Order</h2>
</div>
<div style="overflow-x:auto">
<table class="action-table">
<thead><tr><th>#</th><th>Action</th><th>Severity</th><th>Effort</th><th>Impact</th></tr></thead>
<tbody>{action_rows}</tbody>
</table>
</div>

<div class="cta-box">
  <h3>🎯 Need Help Fixing These Issues?</h3>
  <p>Our security experts can implement all fixes for you — typically in under 24 hours.</p>
  <a href="https://scoreforai.com/contact" class="cta-btn">Book a Free Consultation →</a>
</div>

<div class="cta-box" style="margin-top:16px;border-color:rgba(0,212,255,.2);background:linear-gradient(135deg,rgba(0,212,255,.05),rgba(0,212,255,.02))">
  <h3>🔄 Re-scan After Fixing</h3>
  <p>Verify your improvements with a fresh security scan.</p>
  <a href="https://webseccheck.com" class="cta-btn" style="background:linear-gradient(135deg,#00d4ff,#0099cc)">Scan Again at WebSecCheck.com →</a>
</div>
</section>

</main>

<footer class="report-footer">
<div class="container">
  <div class="footer-brand">Web<span>Sec</span>Check</div>
  <div class="footer-text">Generated on {now} — Report ID: {report_id}</div>
  <div class="footer-disclaimer">This report reflects the security posture of {hostname} at the time of scanning. Security is an ongoing process. This report is confidential and intended solely for the domain owner.</div>
</div>
</footer>

<div class="watermark">Generated by <span>WebSecCheck</span></div>

</body>
</html>"""
