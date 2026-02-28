"""Security.txt check."""

import aiohttp
import asyncio
from typing import List, Dict, Any


async def run_all(url: str) -> List[Dict[str, Any]]:
    """Check for /.well-known/security.txt."""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    base = f"https://{parsed.hostname}"
    target = f"{base}/.well-known/security.txt"
    timeout = aiohttp.ClientTimeout(total=5)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(target, ssl=False, allow_redirects=True) as resp:
                if resp.status == 200:
                    body = await resp.text(errors="replace")
                    has_contact = "contact:" in body.lower()
                    if has_contact:
                        return [{
                            "id": "security_txt",
                            "name": "Security.txt",
                            "category": "Best Practices",
                            "status": "pass",
                            "description": "security.txt is present with contact information.",
                            "details": {"url": target},
                        }]
                    return [{
                        "id": "security_txt",
                        "name": "Security.txt",
                        "category": "Best Practices",
                        "status": "warn",
                        "description": "security.txt exists but may be missing required 'Contact' field.",
                        "details": {"url": target},
                    }]
    except Exception:
        pass
    return [{
        "id": "security_txt",
        "name": "Security.txt",
        "category": "Best Practices",
        "status": "warn",
        "description": "No security.txt found at /.well-known/security.txt. Add one to help security researchers report vulnerabilities.",
    }]
