"""Email security checks: BIMI, MTA-STS, DANE."""

import asyncio
import dns.resolver
from typing import List, Dict, Any

TIMEOUT = 5


async def _query_txt(domain: str) -> str:
    def _resolve():
        try:
            answers = dns.resolver.resolve(domain, "TXT", lifetime=TIMEOUT)
            return " ".join(b.decode() for rdata in answers for b in rdata.strings)
        except Exception:
            return ""
    return await asyncio.get_event_loop().run_in_executor(None, _resolve)


async def check_bimi(domain: str) -> Dict[str, Any]:
    txt = await _query_txt(f"default._bimi.{domain}")
    if "v=bimi1" in txt.lower():
        return {
            "id": "email_bimi",
            "name": "BIMI Record",
            "category": "Email Security",
            "status": "pass",
            "description": "BIMI record is configured for brand logo in email clients.",
            "details": {"record": txt[:200]},
        }
    return {
        "id": "email_bimi",
        "name": "BIMI Record",
        "category": "Email Security",
        "status": "warn",
        "description": "No BIMI record found. Consider adding one to display your brand logo in email clients.",
    }


async def check_mta_sts(domain: str) -> Dict[str, Any]:
    txt = await _query_txt(f"_mta-sts.{domain}")
    if "v=stsv1" in txt.lower():
        return {
            "id": "email_mta_sts",
            "name": "MTA-STS",
            "category": "Email Security",
            "status": "pass",
            "description": "MTA-STS is configured to enforce TLS for email delivery.",
            "details": {"record": txt[:200]},
        }
    return {
        "id": "email_mta_sts",
        "name": "MTA-STS",
        "category": "Email Security",
        "status": "warn",
        "description": "No MTA-STS record found. Consider adding it to enforce TLS for incoming email.",
    }


async def check_dane(domain: str) -> Dict[str, Any]:
    """Check for DANE/TLSA records."""
    def _resolve():
        try:
            answers = dns.resolver.resolve(f"_25._tcp.{domain}", "TLSA", lifetime=TIMEOUT)
            return [str(r) for r in answers]
        except Exception:
            return []
    records = await asyncio.get_event_loop().run_in_executor(None, _resolve)
    if records:
        return {
            "id": "email_dane",
            "name": "DANE/TLSA",
            "category": "Email Security",
            "status": "pass",
            "description": "DANE/TLSA records found for email transport security.",
            "details": {"records": records[:3]},
        }
    return {
        "id": "email_dane",
        "name": "DANE/TLSA",
        "category": "Email Security",
        "status": "warn",
        "description": "No DANE/TLSA records found. Consider adding them if DNSSEC is enabled.",
    }


async def run_all(domain: str) -> List[Dict[str, Any]]:
    results = await asyncio.gather(
        check_bimi(domain),
        check_mta_sts(domain),
        check_dane(domain),
        return_exceptions=True,
    )
    return [r if isinstance(r, dict) else {
        "id": "email_error", "name": "Email Check Error", "category": "Email Security",
        "status": "warn", "description": str(r),
    } for r in results]
