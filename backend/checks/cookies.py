"""Cookie security checks: Secure, HttpOnly, SameSite flags."""

from typing import List, Dict, Any
from http.cookies import SimpleCookie


async def run_all(raw_cookies: List[str]) -> List[Dict[str, Any]]:
    if not raw_cookies:
        return [{
            "id": "cookie_security",
            "name": "Cookie Security",
            "category": "Cookies",
            "status": "pass",
            "description": "No cookies detected on the initial response.",
        }]

    issues = []
    for cookie_str in raw_cookies:
        lower = cookie_str.lower()
        name = cookie_str.split("=")[0].strip() if "=" in cookie_str else "unknown"

        if "secure" not in lower:
            issues.append(f"Cookie '{name}' missing Secure flag")
        if "httponly" not in lower:
            issues.append(f"Cookie '{name}' missing HttpOnly flag")
        if "samesite" not in lower:
            issues.append(f"Cookie '{name}' missing SameSite attribute")

    if issues:
        return [{
            "id": "cookie_security",
            "name": "Cookie Security",
            "category": "Cookies",
            "status": "warn" if len(issues) < 3 else "fail",
            "description": f"Cookie security issues found: {'; '.join(issues[:5])}.",
            "details": {"issues": issues[:10], "cookies_analyzed": len(raw_cookies)},
        }]

    return [{
        "id": "cookie_security",
        "name": "Cookie Security",
        "category": "Cookies",
        "status": "pass",
        "description": f"All {len(raw_cookies)} cookie(s) have Secure, HttpOnly, and SameSite flags.",
        "details": {"cookies_analyzed": len(raw_cookies)},
    }]
