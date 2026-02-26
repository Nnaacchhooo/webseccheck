"""SSL/TLS security checks: certificate validity, expiration, protocol version, HSTS."""

import ssl
import socket
import asyncio
from datetime import datetime, timezone
from typing import List, Dict, Any
from urllib.parse import urlparse


TIMEOUT = 5


def _get_cert_info(hostname: str, port: int = 443) -> Dict[str, Any]:
    """Connect via TLS and return cert + protocol info."""
    ctx = ssl.create_default_context()
    with socket.create_connection((hostname, port), timeout=TIMEOUT) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()
            protocol = ssock.version()
            return {"cert": cert, "protocol": protocol}


async def check_certificate_validity(hostname: str) -> Dict[str, Any]:
    """Check if the SSL certificate is valid and trusted."""
    try:
        info = await asyncio.wait_for(
            asyncio.get_event_loop().run_in_executor(None, _get_cert_info, hostname),
            timeout=TIMEOUT,
        )
        return {
            "id": "ssl_certificate_validity",
            "name": "SSL Certificate Validity",
            "category": "SSL/TLS",
            "status": "pass",
            "description": "SSL certificate is valid and trusted.",
            "details": {"issuer": dict(x[0] for x in info["cert"].get("issuer", []))},
        }
    except ssl.SSLCertVerificationError as e:
        return {
            "id": "ssl_certificate_validity",
            "name": "SSL Certificate Validity",
            "category": "SSL/TLS",
            "status": "fail",
            "description": f"SSL certificate validation failed: {e}",
        }
    except Exception as e:
        return {
            "id": "ssl_certificate_validity",
            "name": "SSL Certificate Validity",
            "category": "SSL/TLS",
            "status": "fail",
            "description": f"Could not establish SSL connection: {type(e).__name__}",
        }


async def check_certificate_expiration(hostname: str) -> Dict[str, Any]:
    """Check certificate expiration date."""
    try:
        info = await asyncio.wait_for(
            asyncio.get_event_loop().run_in_executor(None, _get_cert_info, hostname),
            timeout=TIMEOUT,
        )
        cert = info["cert"]
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = (not_after - datetime.now(timezone.utc)).days

        if days_left < 0:
            status, desc = "fail", f"Certificate expired {abs(days_left)} days ago."
        elif days_left < 30:
            status, desc = "warn", f"Certificate expires in {days_left} days."
        else:
            status, desc = "pass", f"Certificate valid for {days_left} more days."

        return {
            "id": "ssl_certificate_expiration",
            "name": "SSL Certificate Expiration",
            "category": "SSL/TLS",
            "status": status,
            "description": desc,
            "details": {"expires": cert["notAfter"], "days_remaining": days_left},
        }
    except Exception as e:
        return {
            "id": "ssl_certificate_expiration",
            "name": "SSL Certificate Expiration",
            "category": "SSL/TLS",
            "status": "fail",
            "description": f"Could not check certificate expiration: {type(e).__name__}",
        }


async def check_tls_version(hostname: str) -> Dict[str, Any]:
    """Check TLS protocol version."""
    try:
        info = await asyncio.wait_for(
            asyncio.get_event_loop().run_in_executor(None, _get_cert_info, hostname),
            timeout=TIMEOUT,
        )
        protocol = info["protocol"]
        if protocol in ("TLSv1.3",):
            status, desc = "pass", f"Using {protocol} (recommended)."
        elif protocol in ("TLSv1.2",):
            status, desc = "pass", f"Using {protocol} (acceptable)."
        else:
            status, desc = "fail", f"Using outdated {protocol}. Upgrade to TLS 1.2+."

        return {
            "id": "ssl_tls_version",
            "name": "TLS Protocol Version",
            "category": "SSL/TLS",
            "status": status,
            "description": desc,
            "details": {"protocol": protocol},
        }
    except Exception as e:
        return {
            "id": "ssl_tls_version",
            "name": "TLS Protocol Version",
            "category": "SSL/TLS",
            "status": "fail",
            "description": f"Could not determine TLS version: {type(e).__name__}",
        }


async def check_hsts(headers: Dict[str, str]) -> Dict[str, Any]:
    """Check for HTTP Strict Transport Security header."""
    hsts = headers.get("strict-transport-security", "")
    if hsts:
        details = {"value": hsts}
        if "max-age" in hsts.lower():
            try:
                max_age = int([p.split("=")[1] for p in hsts.split(";") if "max-age" in p.lower()][0].strip())
                details["max_age_seconds"] = max_age
                if max_age < 31536000:
                    return {
                        "id": "ssl_hsts",
                        "name": "HTTP Strict Transport Security",
                        "category": "SSL/TLS",
                        "status": "warn",
                        "description": f"HSTS max-age is {max_age}s. Recommended: at least 31536000 (1 year).",
                        "details": details,
                    }
            except (IndexError, ValueError):
                pass
        return {
            "id": "ssl_hsts",
            "name": "HTTP Strict Transport Security",
            "category": "SSL/TLS",
            "status": "pass",
            "description": "HSTS is enabled.",
            "details": details,
        }
    return {
        "id": "ssl_hsts",
        "name": "HTTP Strict Transport Security",
        "category": "SSL/TLS",
        "status": "fail",
        "description": "HSTS header is missing. Enable it to prevent protocol downgrade attacks.",
    }


async def run_all(hostname: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
    """Run all SSL/TLS checks."""
    results = await asyncio.gather(
        check_certificate_validity(hostname),
        check_certificate_expiration(hostname),
        check_tls_version(hostname),
        check_hsts(headers),
        return_exceptions=True,
    )
    return [r if isinstance(r, dict) else _error_result(r) for r in results]


def _error_result(e: Exception) -> Dict[str, Any]:
    return {
        "id": "ssl_error",
        "name": "SSL/TLS Check Error",
        "category": "SSL/TLS",
        "status": "fail",
        "description": f"Unexpected error: {e}",
    }
