"""Open Redirect Detection: check for common open redirect patterns in response headers."""

import re
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qs


REDIRECT_PARAMS = ["url", "redirect", "next", "return", "returnurl", "redirect_uri", "return_to", "goto", "destination", "rurl", "target"]


async def run_all(headers: dict, url: str) -> List[Dict[str, Any]]:
    issues = []

    # Check Location header for external redirects
    location = headers.get("location", "")
    if location:
        parsed_orig = urlparse(url)
        parsed_loc = urlparse(location)
        if parsed_loc.hostname and parsed_loc.hostname != parsed_orig.hostname:
            issues.append(f"Redirects to external domain: {parsed_loc.hostname}")

    # Check if URL contains redirect-like query parameters (common open redirect vectors)
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    for param in REDIRECT_PARAMS:
        if param in query_params:
            val = query_params[param][0]
            if val.startswith(("http://", "https://", "//", "/\\")):
                issues.append(f"Query parameter '{param}' contains redirect URL: {val[:80]}")

    # Check Refresh header
    refresh = headers.get("refresh", "")
    if refresh:
        match = re.search(r'url\s*=\s*(https?://[^\s;]+)', refresh, re.IGNORECASE)
        if match:
            issues.append(f"Refresh header redirects to: {match.group(1)[:80]}")

    if issues:
        return [{
            "id": "open_redirect",
            "name": "Open Redirect",
            "category": "Redirects",
            "status": "warn",
            "severity": "medium",
            "description": f"Potential open redirect pattern(s) detected: {'; '.join(issues[:3])}.",
            "details": {"issues": issues[:5]},
        }]

    return [{
        "id": "open_redirect",
        "name": "Open Redirect",
        "category": "Redirects",
        "status": "pass",
        "severity": "medium",
        "description": "No open redirect patterns detected in response headers.",
        "details": {},
    }]
