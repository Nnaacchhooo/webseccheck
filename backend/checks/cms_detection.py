"""Basic CMS detection: WordPress, Drupal, Joomla version exposure."""

import re
from typing import List, Dict, Any


async def run_all(body: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
    detections = []

    # WordPress
    wp_version = None
    m = re.search(r'<meta[^>]+generator[^>]+WordPress\s*([\d.]+)?', body, re.I)
    if m:
        wp_version = m.group(1)
    if not wp_version and '/wp-content/' in body:
        wp_version = "detected"
    if not wp_version and '/wp-includes/' in body:
        wp_version = "detected"

    # Drupal
    drupal_version = None
    m = re.search(r'<meta[^>]+generator[^>]+Drupal\s*([\d.]+)?', body, re.I)
    if m:
        drupal_version = m.group(1)
    if not drupal_version and ('Drupal.settings' in body or '/sites/default/files' in body):
        drupal_version = "detected"

    # Joomla
    joomla_version = None
    m = re.search(r'<meta[^>]+generator[^>]+Joomla[!]?\s*([\d.]+)?', body, re.I)
    if m:
        joomla_version = m.group(1)
    if not joomla_version and '/media/jui/' in body:
        joomla_version = "detected"

    cms_found = []
    if wp_version:
        cms_found.append(("WordPress", wp_version))
    if drupal_version:
        cms_found.append(("Drupal", drupal_version))
    if joomla_version:
        cms_found.append(("Joomla", joomla_version))

    if not cms_found:
        return [{
            "id": "cms_detection",
            "name": "CMS Version Exposure",
            "category": "CMS",
            "status": "pass",
            "description": "No common CMS (WordPress/Drupal/Joomla) version exposure detected.",
        }]

    # Check if actual version numbers are exposed
    version_exposed = any(v not in (None, "detected") for _, v in cms_found)
    cms_str = ", ".join(f"{name} {ver}" for name, ver in cms_found)

    if version_exposed:
        return [{
            "id": "cms_detection",
            "name": "CMS Version Exposure",
            "category": "CMS",
            "status": "warn",
            "description": f"CMS version exposed: {cms_str}. Remove version meta tags to reduce attack surface.",
            "details": {"cms": [{"name": n, "version": v} for n, v in cms_found]},
        }]

    return [{
        "id": "cms_detection",
        "name": "CMS Version Exposure",
        "category": "CMS",
        "status": "pass",
        "description": f"CMS detected ({cms_str}) but version number not exposed in HTML.",
        "details": {"cms": [{"name": n, "version": v} for n, v in cms_found]},
    }]
