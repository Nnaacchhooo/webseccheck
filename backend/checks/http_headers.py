"""HTTP security headers checks."""

from typing import List, Dict, Any


def _check_header(headers: Dict[str, str], header_name: str, check_id: str,
                   display_name: str, missing_msg: str, present_msg: str,
                   missing_status: str = "fail") -> Dict[str, Any]:
    value = headers.get(header_name.lower(), "")
    if value:
        return {
            "id": check_id,
            "name": display_name,
            "category": "HTTP Headers",
            "status": "pass",
            "description": present_msg,
            "details": {"value": value},
        }
    return {
        "id": check_id,
        "name": display_name,
        "category": "HTTP Headers",
        "status": missing_status,
        "description": missing_msg,
    }


async def run_all(headers: Dict[str, str]) -> List[Dict[str, Any]]:
    results = [
        _check_header(
            headers, "content-security-policy", "header_csp",
            "Content Security Policy",
            "CSP header is missing. Add it to prevent XSS and data injection attacks.",
            "Content Security Policy is configured.",
        ),
        _check_header(
            headers, "x-frame-options", "header_x_frame_options",
            "X-Frame-Options",
            "X-Frame-Options header is missing. Your site may be vulnerable to clickjacking.",
            "X-Frame-Options is set.",
        ),
        _check_header(
            headers, "x-content-type-options", "header_x_content_type_options",
            "X-Content-Type-Options",
            "X-Content-Type-Options header is missing. Set it to 'nosniff' to prevent MIME-type sniffing.",
            "X-Content-Type-Options is set.",
        ),
        _check_header(
            headers, "referrer-policy", "header_referrer_policy",
            "Referrer-Policy",
            "Referrer-Policy header is missing. Configure it to control referrer information leakage.",
            "Referrer-Policy is configured.",
        ),
        _check_header(
            headers, "permissions-policy", "header_permissions_policy",
            "Permissions-Policy",
            "Permissions-Policy header is missing. Use it to control browser feature access.",
            "Permissions-Policy is configured.",
        ),
        # New checks
        _check_header(
            headers, "x-xss-protection", "header_x_xss_protection",
            "X-XSS-Protection",
            "X-XSS-Protection header is missing. While deprecated, it provides defense-in-depth for older browsers.",
            "X-XSS-Protection header is set.",
            missing_status="warn",
        ),
        _check_header(
            headers, "cross-origin-opener-policy", "header_cross_origin_opener",
            "Cross-Origin-Opener-Policy",
            "Cross-Origin-Opener-Policy is missing. Set it to isolate your browsing context.",
            "Cross-Origin-Opener-Policy is configured.",
            missing_status="warn",
        ),
        _check_header(
            headers, "cross-origin-embedder-policy", "header_cross_origin_embedder",
            "Cross-Origin-Embedder-Policy",
            "Cross-Origin-Embedder-Policy is missing. Set it to control cross-origin resource loading.",
            "Cross-Origin-Embedder-Policy is configured.",
            missing_status="warn",
        ),
        _check_header(
            headers, "cross-origin-resource-policy", "header_cross_origin_resource",
            "Cross-Origin-Resource-Policy",
            "Cross-Origin-Resource-Policy is missing. Set it to protect resources from cross-origin access.",
            "Cross-Origin-Resource-Policy is configured.",
            missing_status="warn",
        ),
        _check_header(
            headers, "x-dns-prefetch-control", "header_x_dns_prefetch",
            "X-DNS-Prefetch-Control",
            "X-DNS-Prefetch-Control is not set. Consider setting it to 'off' to prevent DNS prefetching privacy leaks.",
            "X-DNS-Prefetch-Control is set.",
            missing_status="warn",
        ),
        _check_header(
            headers, "expect-ct", "header_expect_ct",
            "Expect-CT",
            "Expect-CT header is not set. While deprecated, it signals Certificate Transparency enforcement.",
            "Expect-CT header is set.",
            missing_status="warn",
        ),
    ]

    # Cache-Control check (more nuanced)
    cache_control = headers.get("cache-control", "")
    if cache_control:
        cc_lower = cache_control.lower()
        if "no-store" in cc_lower or "private" in cc_lower:
            results.append({
                "id": "header_cache_control",
                "name": "Cache-Control",
                "category": "HTTP Headers",
                "status": "pass",
                "description": "Cache-Control is properly configured to prevent sensitive data caching.",
                "details": {"value": cache_control},
            })
        else:
            results.append({
                "id": "header_cache_control",
                "name": "Cache-Control",
                "category": "HTTP Headers",
                "status": "warn",
                "description": f"Cache-Control is set but may allow caching of sensitive data: '{cache_control}'. Consider adding 'no-store' for sensitive pages.",
                "details": {"value": cache_control},
            })
    else:
        results.append({
            "id": "header_cache_control",
            "name": "Cache-Control",
            "category": "HTTP Headers",
            "status": "warn",
            "description": "Cache-Control header is missing. Set it to prevent caching of sensitive data.",
        })

    return results
