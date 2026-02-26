"""Mixed Content Detection: check if HTTPS pages load HTTP resources."""

import re
from typing import List, Dict, Any


HTTP_RESOURCE_PATTERNS = [
    re.compile(r'(?:src|href|action)\s*=\s*["\']http://', re.IGNORECASE),
    re.compile(r'url\s*\(\s*["\']?http://', re.IGNORECASE),
    re.compile(r'<link[^>]+href\s*=\s*["\']http://', re.IGNORECASE),
    re.compile(r'<script[^>]+src\s*=\s*["\']http://', re.IGNORECASE),
    re.compile(r'<img[^>]+src\s*=\s*["\']http://', re.IGNORECASE),
    re.compile(r'<iframe[^>]+src\s*=\s*["\']http://', re.IGNORECASE),
]


async def run_all(body: str, url: str) -> List[Dict[str, Any]]:
    is_https = url.startswith("https://")

    if not is_https:
        return [{
            "id": "mixed_content",
            "name": "Mixed Content",
            "category": "Content Security",
            "status": "warn",
            "severity": "medium",
            "description": "Site is served over HTTP — mixed content check not applicable, but HTTPS is recommended.",
            "details": {"note": "Site does not use HTTPS"},
        }]

    http_refs = []
    for pattern in HTTP_RESOURCE_PATTERNS:
        matches = pattern.findall(body)
        http_refs.extend(matches)

    # Also extract actual URLs for details
    url_pattern = re.compile(r'(?:src|href|action)\s*=\s*["\']?(http://[^\s"\'<>]+)', re.IGNORECASE)
    found_urls = list(set(url_pattern.findall(body)))[:10]

    if found_urls:
        return [{
            "id": "mixed_content",
            "name": "Mixed Content",
            "category": "Content Security",
            "status": "fail",
            "severity": "high",
            "description": f"Found {len(found_urls)} HTTP resource(s) loaded on an HTTPS page (mixed content).",
            "details": {"http_resources": found_urls[:10], "count": len(found_urls)},
        }]

    return [{
        "id": "mixed_content",
        "name": "Mixed Content",
        "category": "Content Security",
        "status": "pass",
        "severity": "high",
        "description": "No mixed content detected — all resources appear to load over HTTPS.",
        "details": {},
    }]
