"""Server exposure checks: version disclosure, X-Powered-By, debug headers, directory listing, error pages, admin panels."""

import re
import aiohttp
import asyncio
from typing import List, Dict, Any


async def _fetch_path(base_url: str, path: str) -> tuple:
    """Fetch a path and return (status_code, headers, body_snippet)."""
    timeout = aiohttp.ClientTimeout(total=5)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(f"{base_url}{path}", allow_redirects=False, ssl=False) as resp:
                body = await resp.text(errors="replace")
                return resp.status, dict(resp.headers), body[:5000]
    except Exception:
        return 0, {}, ""


async def run_all(headers: Dict[str, str], url: str = "") -> List[Dict[str, Any]]:
    results = []

    # Server header
    server = headers.get("server", "")
    if server:
        has_version = bool(re.search(r'\d+\.', server))
        if has_version:
            results.append({
                "id": "server_version_disclosure",
                "name": "Server Version Disclosure",
                "category": "Server Exposure",
                "status": "warn",
                "description": f"Server header discloses version: '{server}'. Remove version info to reduce attack surface.",
                "details": {"server": server},
            })
        else:
            results.append({
                "id": "server_version_disclosure",
                "name": "Server Version Disclosure",
                "category": "Server Exposure",
                "status": "pass",
                "description": "Server header present but no version number disclosed.",
                "details": {"server": server},
            })
    else:
        results.append({
            "id": "server_version_disclosure",
            "name": "Server Version Disclosure",
            "category": "Server Exposure",
            "status": "pass",
            "description": "Server header is not exposed.",
        })

    # X-Powered-By
    powered_by = headers.get("x-powered-by", "")
    if powered_by:
        results.append({
            "id": "server_x_powered_by",
            "name": "X-Powered-By Leak",
            "category": "Server Exposure",
            "status": "warn",
            "description": f"X-Powered-By header exposes technology: '{powered_by}'. Remove it.",
            "details": {"x_powered_by": powered_by},
        })
    else:
        results.append({
            "id": "server_x_powered_by",
            "name": "X-Powered-By Leak",
            "category": "Server Exposure",
            "status": "pass",
            "description": "X-Powered-By header is not exposed.",
        })

    # Debug headers
    debug_headers = []
    for h in ["x-debug", "x-debug-token", "x-debug-token-link", "x-aspnet-version", "x-aspnetmvc-version"]:
        if h in headers:
            debug_headers.append(f"{h}: {headers[h]}")
    if debug_headers:
        results.append({
            "id": "server_debug_headers",
            "name": "Debug Headers Exposed",
            "category": "Server Exposure",
            "status": "warn",
            "description": f"Debug headers found: {', '.join(debug_headers[:3])}. Remove them in production.",
            "details": {"headers": debug_headers},
        })
    else:
        results.append({
            "id": "server_debug_headers",
            "name": "Debug Headers Exposed",
            "category": "Server Exposure",
            "status": "pass",
            "description": "No debug headers detected.",
        })

    # Checks that need URL
    if url:
        # Error page info disclosure
        try:
            status_code, err_headers, err_body = await _fetch_path(url.rstrip("/"), "/nonexistent-path-wsc-test-404")
            server_info_patterns = [
                r'Apache/[\d.]+', r'nginx/[\d.]+', r'Microsoft-IIS/[\d.]+',
                r'PHP/[\d.]+', r'Python/[\d.]+', r'Node\.js',
                r'<address>.*?Server at', r'Traceback \(most recent call',
                r'Stack Trace:', r'Exception Details:',
            ]
            found_leaks = []
            for pat in server_info_patterns:
                m = re.search(pat, err_body, re.I)
                if m:
                    found_leaks.append(m.group(0)[:60])
            if found_leaks:
                results.append({
                    "id": "server_error_pages",
                    "name": "Error Page Information Leak",
                    "category": "Server Exposure",
                    "status": "warn",
                    "description": f"Error page reveals server information: {', '.join(found_leaks[:3])}.",
                    "details": {"leaks": found_leaks[:5]},
                })
            else:
                results.append({
                    "id": "server_error_pages",
                    "name": "Error Page Information Leak",
                    "category": "Server Exposure",
                    "status": "pass",
                    "description": "Error pages do not reveal server technology details.",
                })
        except Exception:
            results.append({
                "id": "server_error_pages",
                "name": "Error Page Information Leak",
                "category": "Server Exposure",
                "status": "pass",
                "description": "Could not test error pages (connection issue).",
            })

        # Admin panels
        admin_paths = ["/admin", "/wp-admin", "/administrator", "/wp-login.php", "/admin/login", "/cpanel", "/phpmyadmin"]
        found_panels = []
        try:
            for path in admin_paths:
                status_code, _, _ = await _fetch_path(url.rstrip("/"), path)
                if status_code in (200, 301, 302, 303, 307, 308, 401, 403):
                    found_panels.append(f"{path} ({status_code})")
                if len(found_panels) >= 3:
                    break
        except Exception:
            pass
        if found_panels:
            results.append({
                "id": "server_admin_panels",
                "name": "Admin Panel Exposure",
                "category": "Server Exposure",
                "status": "warn",
                "description": f"Admin panel paths accessible: {', '.join(found_panels[:3])}. Restrict access.",
                "details": {"panels": found_panels},
            })
        else:
            results.append({
                "id": "server_admin_panels",
                "name": "Admin Panel Exposure",
                "category": "Server Exposure",
                "status": "pass",
                "description": "No common admin panels detected at standard paths.",
            })

        # Directory listing
        dir_paths = ["/images/", "/assets/", "/uploads/", "/static/", "/css/", "/js/"]
        dir_listing_found = False
        try:
            for path in dir_paths:
                status_code, _, dir_body = await _fetch_path(url.rstrip("/"), path)
                if status_code == 200 and ("Index of" in dir_body or "Directory listing" in dir_body.lower()):
                    dir_listing_found = True
                    results.append({
                        "id": "server_directory_listing",
                        "name": "Directory Listing",
                        "category": "Server Exposure",
                        "status": "warn",
                        "description": f"Directory listing enabled at {path}. Disable it to prevent information disclosure.",
                        "details": {"path": path},
                    })
                    break
        except Exception:
            pass
        if not dir_listing_found:
            results.append({
                "id": "server_directory_listing",
                "name": "Directory Listing",
                "category": "Server Exposure",
                "status": "pass",
                "description": "No directory listing detected on common paths.",
            })
    else:
        # Add placeholder results when URL not available
        for check_id, name in [("server_error_pages", "Error Page Information Leak"),
                                ("server_admin_panels", "Admin Panel Exposure"),
                                ("server_directory_listing", "Directory Listing")]:
            results.append({
                "id": check_id,
                "name": name,
                "category": "Server Exposure",
                "status": "pass",
                "description": "Check skipped (URL not available).",
            })

    return results
