"""DNS security checks: SPF, DKIM, DMARC records."""

import asyncio
import dns.resolver
from typing import List, Dict, Any

TIMEOUT = 5


async def _query_txt(domain: str, prefix: str = "") -> str:
    target = f"{prefix}.{domain}" if prefix else domain
    def _resolve():
        try:
            answers = dns.resolver.resolve(target, "TXT", lifetime=TIMEOUT)
            return " ".join(b.decode() for rdata in answers for b in rdata.strings)
        except Exception:
            return ""
    return await asyncio.get_event_loop().run_in_executor(None, _resolve)


async def check_spf(domain: str) -> Dict[str, Any]:
    txt = await _query_txt(domain)
    if "v=spf1" in txt:
        return {
            "id": "dns_spf",
            "name": "SPF Record",
            "category": "DNS",
            "status": "pass",
            "description": "SPF record is configured.",
            "details": {"record": txt},
        }
    return {
        "id": "dns_spf",
        "name": "SPF Record",
        "category": "DNS",
        "status": "fail",
        "description": "No SPF record found. Add one to prevent email spoofing.",
    }


async def check_dmarc(domain: str) -> Dict[str, Any]:
    txt = await _query_txt(domain, "_dmarc")
    if "v=DMARC1" in txt.upper():
        return {
            "id": "dns_dmarc",
            "name": "DMARC Record",
            "category": "DNS",
            "status": "pass",
            "description": "DMARC record is configured.",
            "details": {"record": txt},
        }
    return {
        "id": "dns_dmarc",
        "name": "DMARC Record",
        "category": "DNS",
        "status": "fail",
        "description": "No DMARC record found. Add one to specify email authentication policy.",
    }


async def check_dkim(domain: str) -> Dict[str, Any]:
    """Check common DKIM selectors."""
    selectors = ["default", "google", "selector1", "selector2", "k1", "mail", "dkim"]
    for sel in selectors:
        txt = await _query_txt(domain, f"{sel}._domainkey")
        if "v=DKIM1" in txt.upper() or "p=" in txt:
            return {
                "id": "dns_dkim",
                "name": "DKIM Record",
                "category": "DNS",
                "status": "pass",
                "description": f"DKIM record found (selector: {sel}).",
                "details": {"selector": sel},
            }
    return {
        "id": "dns_dkim",
        "name": "DKIM Record",
        "category": "DNS",
        "status": "warn",
        "description": "No DKIM record found for common selectors. DKIM may use a custom selector.",
    }


async def run_all(domain: str) -> List[Dict[str, Any]]:
    results = await asyncio.gather(
        check_spf(domain),
        check_dmarc(domain),
        check_dkim(domain),
        return_exceptions=True,
    )
    return [r if isinstance(r, dict) else {
        "id": "dns_error", "name": "DNS Check Error", "category": "DNS",
        "status": "fail", "description": str(r),
    } for r in results]
