"""DNS security checks: SPF, DKIM, DMARC, CAA, DNSSEC records."""

import asyncio
import dns.resolver
import dns.rdatatype
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
    if "V=DMARC1" in txt.upper():
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
    selectors = ["default", "google", "selector1", "selector2", "k1", "mail", "dkim",
                  "resend", "mailchimp", "mandrill", "amazonses", "ses", "sendgrid", "s1", "s2",
                  "cf2024-1", "cf2024-2", "protonmail", "protonmail2", "protonmail3",
                  "mxvault", "smtp", "email", "mailo", "zendesk1", "zendesk2"]
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


async def check_caa(domain: str) -> Dict[str, Any]:
    """Check CAA DNS records."""
    def _resolve():
        try:
            answers = dns.resolver.resolve(domain, "CAA", lifetime=TIMEOUT)
            records = [str(r) for r in answers]
            return records
        except dns.resolver.NoAnswer:
            return []
        except dns.resolver.NXDOMAIN:
            return []
        except Exception:
            return []
    records = await asyncio.get_event_loop().run_in_executor(None, _resolve)
    if records:
        return {
            "id": "dns_caa",
            "name": "CAA Records",
            "category": "DNS",
            "status": "pass",
            "description": f"CAA records configured ({len(records)} record(s)). This limits which CAs can issue certificates.",
            "details": {"records": records[:5]},
        }
    return {
        "id": "dns_caa",
        "name": "CAA Records",
        "category": "DNS",
        "status": "warn",
        "description": "No CAA records found. Consider adding them to restrict which CAs can issue certificates for your domain.",
    }


async def check_dnssec(domain: str) -> Dict[str, Any]:
    """Check if DNSSEC is enabled."""
    def _resolve():
        try:
            request = dns.message.make_query(domain, dns.rdatatype.A, want_dnssec=True)
            request.flags |= dns.flags.AD
            response = dns.query.udp(request, "8.8.8.8", timeout=TIMEOUT)
            # Check if AD (Authenticated Data) flag is set
            return bool(response.flags & dns.flags.AD)
        except Exception:
            return False
    try:
        import dns.message
        import dns.query
        import dns.flags
        is_signed = await asyncio.get_event_loop().run_in_executor(None, _resolve)
        if is_signed:
            return {
                "id": "dns_dnssec",
                "name": "DNSSEC",
                "category": "DNS",
                "status": "pass",
                "description": "DNSSEC is enabled and validated.",
            }
        return {
            "id": "dns_dnssec",
            "name": "DNSSEC",
            "category": "DNS",
            "status": "warn",
            "description": "DNSSEC is not enabled. Consider enabling it to protect against DNS spoofing.",
        }
    except ImportError:
        return {
            "id": "dns_dnssec",
            "name": "DNSSEC",
            "category": "DNS",
            "status": "warn",
            "description": "Could not check DNSSEC (dns.query not available).",
        }


async def run_all(domain: str) -> List[Dict[str, Any]]:
    results = await asyncio.gather(
        check_spf(domain),
        check_dmarc(domain),
        check_dkim(domain),
        check_caa(domain),
        check_dnssec(domain),
        return_exceptions=True,
    )
    return [r if isinstance(r, dict) else {
        "id": "dns_error", "name": "DNS Check Error", "category": "DNS",
        "status": "fail", "description": str(r),
    } for r in results]
