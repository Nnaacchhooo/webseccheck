"""Send report emails via Resend API."""

import os
import requests

RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "re_GC795Zim_B6GKbogAqYZNTfpXPAj9JGUF")
FROM_EMAIL = "WebSecCheck <hello@scoreforai.com>"
BASE_URL = os.environ.get("BASE_URL", "https://pablittus-webseccheck.hf.space")


def send_report_email(to_email: str, token: str, hostname: str, score: int, grade: str) -> bool:
    """Send the report access email via Resend."""
    report_url = f"{BASE_URL}/report/{token}"
    
    grade_color = {"A": "#00ff88", "B": "#00cc33", "C": "#ffd600", "D": "#ff9800", "F": "#ff4444"}.get(grade, "#fff")
    
    html = f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#0a0a0a;font-family:'Segoe UI',system-ui,sans-serif;">
<div style="max-width:600px;margin:0 auto;padding:40px 24px;">
  <div style="text-align:center;margin-bottom:32px;">
    <div style="font-size:28px;font-weight:700;color:#fff;">🛡️ Web<span style="color:#00FF41;">Sec</span>Check</div>
    <div style="font-size:12px;color:#888;letter-spacing:2px;margin-top:4px;">SECURITY ASSESSMENT REPORT</div>
  </div>
  
  <div style="background:#111;border:1px solid #2a2a2a;border-radius:12px;padding:32px;margin-bottom:24px;">
    <h2 style="color:#fff;margin:0 0 8px;font-size:20px;">Your Security Report is Ready</h2>
    <p style="color:#aaa;font-size:15px;line-height:1.7;margin:0 0 24px;">
      We've completed a comprehensive security scan of <strong style="color:#fff;">{hostname}</strong>. 
      Here's your quick summary:
    </p>
    
    <div style="display:flex;gap:16px;margin-bottom:24px;">
      <div style="background:#1a1a1a;border:1px solid #2a2a2a;border-radius:10px;padding:20px;text-align:center;flex:1;">
        <div style="font-size:36px;font-weight:800;color:{grade_color};">{score}</div>
        <div style="font-size:11px;color:#888;text-transform:uppercase;letter-spacing:1px;margin-top:4px;">Score</div>
      </div>
      <div style="background:#1a1a1a;border:1px solid #2a2a2a;border-radius:10px;padding:20px;text-align:center;flex:1;">
        <div style="font-size:36px;font-weight:800;color:{grade_color};">{grade}</div>
        <div style="font-size:11px;color:#888;text-transform:uppercase;letter-spacing:1px;margin-top:4px;">Grade</div>
      </div>
    </div>
    
    <div style="text-align:center;">
      <a href="{report_url}" style="display:inline-block;background:linear-gradient(135deg,#00FF41,#00cc33);color:#000;padding:14px 40px;border-radius:10px;font-weight:700;text-decoration:none;font-size:16px;">
        View Full Report →
      </a>
    </div>
    
    <p style="color:#666;font-size:12px;text-align:center;margin-top:16px;">
      This link is unique to you. Bookmark it to access your report anytime.
    </p>
  </div>
  
  <div style="background:linear-gradient(135deg,rgba(0,255,65,.05),rgba(0,255,65,.02));border:1px solid rgba(0,255,65,.2);border-radius:12px;padding:24px;text-align:center;margin-bottom:24px;">
    <h3 style="color:#fff;font-size:16px;margin:0 0 8px;">Need Help Fixing These Issues?</h3>
    <p style="color:#aaa;font-size:14px;margin:0 0 16px;">Our security experts can implement all fixes for you in under 24 hours.</p>
    <a href="https://scoreforai.com/contact" style="color:#00FF41;font-weight:700;text-decoration:none;font-size:14px;">Book a Free Consultation →</a>
  </div>
  
  <div style="text-align:center;color:#555;font-size:12px;line-height:1.6;">
    <p>© 2026 WebSecCheck by Score for AI</p>
    <p style="margin-top:4px;">This report is confidential and intended solely for the domain owner.</p>
  </div>
</div>
</body>
</html>"""

    try:
        resp = requests.post(
            "https://api.resend.com/emails",
            headers={
                "Authorization": f"Bearer {RESEND_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "from": FROM_EMAIL,
                "to": [to_email],
                "subject": f"🛡️ Your Security Report for {hostname} — Grade {grade}",
                "html": html,
            },
            timeout=10,
        )
        return resp.status_code == 200
    except Exception as e:
        print(f"Email send error: {e}")
        return False
