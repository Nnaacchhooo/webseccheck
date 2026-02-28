"""Content security checks: CSP report-uri, SRI, inline scripts."""

import re
from typing import List, Dict, Any


async def run_all(headers: Dict[str, str], body: str) -> List[Dict[str, Any]]:
    results = []

    # CSP report-uri check
    csp = headers.get("content-security-policy", "")
    if csp:
        has_report = "report-uri" in csp.lower() or "report-to" in csp.lower()
        if has_report:
            results.append({
                "id": "csp_report_uri",
                "name": "CSP Reporting",
                "category": "Content Security",
                "status": "pass",
                "description": "CSP has reporting configured (report-uri/report-to).",
            })
        else:
            results.append({
                "id": "csp_report_uri",
                "name": "CSP Reporting",
                "category": "Content Security",
                "status": "warn",
                "description": "CSP is set but has no report-uri/report-to. Add reporting to monitor violations.",
            })
    else:
        results.append({
            "id": "csp_report_uri",
            "name": "CSP Reporting",
            "category": "Content Security",
            "status": "fail",
            "description": "No CSP header found — reporting cannot be configured without CSP.",
        })

    # External scripts without SRI
    script_tags = re.findall(r'<script[^>]+src=["\']([^"\']+)["\'][^>]*>', body, re.I)
    external_scripts = [s for s in script_tags if s.startswith(("http://", "https://", "//"))]
    # Check which have integrity attribute
    scripts_without_sri = []
    for match in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\'][^>]*>', body, re.I):
        src = match.group(1)
        tag = match.group(0)
        if src.startswith(("http://", "https://", "//")) and "integrity=" not in tag.lower():
            scripts_without_sri.append(src[:100])

    if external_scripts:
        if scripts_without_sri:
            results.append({
                "id": "sri_external_scripts",
                "name": "Subresource Integrity",
                "category": "Content Security",
                "status": "warn",
                "description": f"{len(scripts_without_sri)} external script(s) loaded without SRI integrity attribute.",
                "details": {"without_sri": scripts_without_sri[:5], "total_external": len(external_scripts)},
            })
        else:
            results.append({
                "id": "sri_external_scripts",
                "name": "Subresource Integrity",
                "category": "Content Security",
                "status": "pass",
                "description": f"All {len(external_scripts)} external script(s) have SRI integrity attributes.",
                "details": {"total_external": len(external_scripts)},
            })
    else:
        results.append({
            "id": "sri_external_scripts",
            "name": "Subresource Integrity",
            "category": "Content Security",
            "status": "pass",
            "description": "No external scripts detected.",
        })

    # Inline scripts
    inline_scripts = re.findall(r'<script(?![^>]*\bsrc=)[^>]*>(.+?)</script>', body, re.I | re.S)
    inline_count = len(inline_scripts)
    if inline_count > 5:
        results.append({
            "id": "inline_scripts",
            "name": "Inline Scripts",
            "category": "Content Security",
            "status": "warn",
            "description": f"Found {inline_count} inline scripts. Consider moving them to external files to enable stricter CSP.",
            "details": {"count": inline_count},
        })
    elif inline_count > 0:
        results.append({
            "id": "inline_scripts",
            "name": "Inline Scripts",
            "category": "Content Security",
            "status": "pass",
            "description": f"Found {inline_count} inline script(s). Consider using nonces or hashes in CSP.",
            "details": {"count": inline_count},
        })
    else:
        results.append({
            "id": "inline_scripts",
            "name": "Inline Scripts",
            "category": "Content Security",
            "status": "pass",
            "description": "No inline scripts detected.",
        })

    return results
