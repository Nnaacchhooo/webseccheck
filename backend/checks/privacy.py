"""Privacy checks: trackers, third-party domains."""

import re
from urllib.parse import urlparse
from typing import List, Dict, Any


KNOWN_TRACKERS = {
    "Google Analytics": [r"google-analytics\.com", r"googletagmanager\.com", r"gtag/js"],
    "Facebook Pixel": [r"connect\.facebook\.net", r"facebook\.com/tr"],
    "Hotjar": [r"hotjar\.com"],
    "Mixpanel": [r"mixpanel\.com"],
    "Segment": [r"segment\.com/analytics"],
    "Heap": [r"heap-analytics"],
    "Amplitude": [r"amplitude\.com"],
    "Microsoft Clarity": [r"clarity\.ms"],
    "TikTok Pixel": [r"analytics\.tiktok\.com"],
    "Twitter Pixel": [r"static\.ads-twitter\.com"],
    "LinkedIn Insight": [r"snap\.licdn\.com"],
    "Pinterest Tag": [r"pintrk"],
}


async def run_all(body: str, url: str) -> List[Dict[str, Any]]:
    results = []

    # Tracker detection
    found_trackers = []
    for name, patterns in KNOWN_TRACKERS.items():
        for pat in patterns:
            if re.search(pat, body, re.I):
                found_trackers.append(name)
                break
    if found_trackers:
        results.append({
            "id": "privacy_tracking",
            "name": "Tracking Scripts",
            "category": "Privacy",
            "status": "warn",
            "description": f"Found {len(found_trackers)} tracking service(s): {', '.join(found_trackers[:5])}.",
            "details": {"trackers": found_trackers},
        })
    else:
        results.append({
            "id": "privacy_tracking",
            "name": "Tracking Scripts",
            "category": "Privacy",
            "status": "pass",
            "description": "No known tracking scripts detected.",
        })

    # Third-party domains
    parsed_url = urlparse(url)
    site_domain = parsed_url.hostname or ""
    # Extract base domain (last two parts)
    site_parts = site_domain.split(".")
    site_base = ".".join(site_parts[-2:]) if len(site_parts) >= 2 else site_domain

    # Find all external URLs
    url_pattern = re.compile(r'(?:src|href)=["\'](?:https?:)?//([^/\s"\']+)', re.I)
    all_domains = set()
    for match in url_pattern.finditer(body):
        domain = match.group(1).lower()
        domain_parts = domain.split(".")
        domain_base = ".".join(domain_parts[-2:]) if len(domain_parts) >= 2 else domain
        if domain_base != site_base:
            all_domains.add(domain)

    third_party_count = len(all_domains)
    if third_party_count > 10:
        results.append({
            "id": "privacy_third_party",
            "name": "Third-Party Domains",
            "category": "Privacy",
            "status": "warn",
            "description": f"Page loads resources from {third_party_count} third-party domains. Consider reducing external dependencies.",
            "details": {"count": third_party_count, "domains": sorted(list(all_domains))[:15]},
        })
    elif third_party_count > 0:
        results.append({
            "id": "privacy_third_party",
            "name": "Third-Party Domains",
            "category": "Privacy",
            "status": "pass",
            "description": f"Page loads resources from {third_party_count} third-party domain(s).",
            "details": {"count": third_party_count, "domains": sorted(list(all_domains))[:10]},
        })
    else:
        results.append({
            "id": "privacy_third_party",
            "name": "Third-Party Domains",
            "category": "Privacy",
            "status": "pass",
            "description": "No third-party domains detected.",
        })

    return results
