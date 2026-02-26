"""Server exposure checks: server version disclosure, X-Powered-By leaks."""

from typing import List, Dict, Any


async def run_all(headers: Dict[str, str]) -> List[Dict[str, Any]]:
    results = []

    # Server header
    server = headers.get("server", "")
    if server:
        # Check if version number is disclosed
        import re
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

    return results
