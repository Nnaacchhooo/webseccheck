"""HTTP security headers checks: CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy."""

from typing import List, Dict, Any


def _check_header(headers: Dict[str, str], header_name: str, check_id: str,
                   display_name: str, missing_msg: str, present_msg: str) -> Dict[str, Any]:
    value = headers.get(header_name.lower(), "")
    if value:
        return {
            "id": check_id,
            "name": display_name,
            "category": "HTTP Headers",
            "status": "pass",
            "description": present_msg,
            "details": {"value": value},
        }
    return {
        "id": check_id,
        "name": display_name,
        "category": "HTTP Headers",
        "status": "fail",
        "description": missing_msg,
    }


async def run_all(headers: Dict[str, str]) -> List[Dict[str, Any]]:
    return [
        _check_header(
            headers, "content-security-policy", "header_csp",
            "Content Security Policy",
            "CSP header is missing. Add it to prevent XSS and data injection attacks.",
            "Content Security Policy is configured.",
        ),
        _check_header(
            headers, "x-frame-options", "header_x_frame_options",
            "X-Frame-Options",
            "X-Frame-Options header is missing. Your site may be vulnerable to clickjacking.",
            "X-Frame-Options is set.",
        ),
        _check_header(
            headers, "x-content-type-options", "header_x_content_type_options",
            "X-Content-Type-Options",
            "X-Content-Type-Options header is missing. Set it to 'nosniff' to prevent MIME-type sniffing.",
            "X-Content-Type-Options is set.",
        ),
        _check_header(
            headers, "referrer-policy", "header_referrer_policy",
            "Referrer-Policy",
            "Referrer-Policy header is missing. Configure it to control referrer information leakage.",
            "Referrer-Policy is configured.",
        ),
        _check_header(
            headers, "permissions-policy", "header_permissions_policy",
            "Permissions-Policy",
            "Permissions-Policy header is missing. Use it to control browser feature access.",
            "Permissions-Policy is configured.",
        ),
    ]
