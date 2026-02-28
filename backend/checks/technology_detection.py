"""Technology detection checks: frameworks, libraries, WAF."""

import re
from typing import List, Dict, Any


async def run_all(headers: Dict[str, str], body: str) -> List[Dict[str, Any]]:
    results = []

    # Framework disclosure
    frameworks = []
    powered_by = headers.get("x-powered-by", "")
    if powered_by:
        frameworks.append(powered_by)
    generator_match = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)
    if not generator_match:
        generator_match = re.search(r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']generator["\']', body, re.I)
    if generator_match:
        frameworks.append(generator_match.group(1))
    if frameworks:
        results.append({
            "id": "tech_framework_disclosure",
            "name": "Framework Disclosure",
            "category": "Technology",
            "status": "warn",
            "description": f"Framework/technology disclosed: {', '.join(frameworks)}. Consider hiding this information.",
            "details": {"frameworks": frameworks},
        })
    else:
        results.append({
            "id": "tech_framework_disclosure",
            "name": "Framework Disclosure",
            "category": "Technology",
            "status": "pass",
            "description": "No framework information disclosed in headers or meta tags.",
        })

    # Vulnerable JS libraries
    vuln_libs = []
    jquery_match = re.search(r'jquery[.-]?([\d.]+)', body, re.I)
    if jquery_match:
        ver = jquery_match.group(1)
        try:
            major, minor = int(ver.split(".")[0]), int(ver.split(".")[1]) if "." in ver else 0
            if major < 3 or (major == 3 and minor < 5):
                vuln_libs.append(f"jQuery {ver} (outdated)")
        except (ValueError, IndexError):
            pass
    angular_match = re.search(r'angular[.-]?(1\.[\d.]+)', body, re.I)
    if angular_match:
        vuln_libs.append(f"AngularJS {angular_match.group(1)} (EOL)")
    if 'bootstrap/3.' in body.lower() or 'bootstrap@3.' in body.lower():
        vuln_libs.append("Bootstrap 3.x (outdated)")

    if vuln_libs:
        results.append({
            "id": "tech_javascript_libraries",
            "name": "Outdated JavaScript Libraries",
            "category": "Technology",
            "status": "warn",
            "description": f"Potentially outdated libraries detected: {', '.join(vuln_libs)}.",
            "details": {"libraries": vuln_libs},
        })
    else:
        results.append({
            "id": "tech_javascript_libraries",
            "name": "Outdated JavaScript Libraries",
            "category": "Technology",
            "status": "pass",
            "description": "No known outdated JavaScript libraries detected.",
        })

    # WAF detection
    waf_signatures = {
        "cloudflare": ["cf-ray", "cf-cache-status", "cf-request-id"],
        "AWS WAF": ["x-amzn-requestid", "x-amz-cf-id"],
        "Akamai": ["x-akamai-transformed", "akamai-grn"],
        "Sucuri": ["x-sucuri-id", "x-sucuri-cache"],
        "Fastly": ["x-fastly-request-id", "fastly-restarts"],
        "Incapsula": ["x-iinfo", "x-cdn"],
    }
    detected_waf = []
    for waf_name, sigs in waf_signatures.items():
        for sig in sigs:
            if sig in headers:
                detected_waf.append(waf_name)
                break
    # Also check server header
    server = headers.get("server", "").lower()
    if "cloudflare" in server:
        detected_waf.append("Cloudflare") if "Cloudflare" not in detected_waf and "cloudflare" not in detected_waf else None

    if detected_waf:
        results.append({
            "id": "tech_waf_detection",
            "name": "WAF Detection",
            "category": "Technology",
            "status": "pass",
            "description": f"Web Application Firewall detected: {', '.join(set(detected_waf))}. Good protection layer.",
            "details": {"waf": list(set(detected_waf))},
        })
    else:
        results.append({
            "id": "tech_waf_detection",
            "name": "WAF Detection",
            "category": "Technology",
            "status": "warn",
            "description": "No Web Application Firewall detected. Consider adding one for extra protection.",
        })

    return results
