"""WebSecCheck - FastAPI backend for passive web security scanning."""

import asyncio
import time
from typing import Optional
from urllib.parse import urlparse

import aiohttp
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, field_validator

from checks import ssl_tls, http_headers, dns_records, server_exposure, cookies, cms_detection, mixed_content, redirects
from report_generator import generate_pdf
from token_manager import generate_token, validate_token
from email_sender import send_report_email
from report_html import generate_report_html

app = FastAPI(
    title="WebSecCheck API",
    description="Passive web security scanner — checks SSL/TLS, HTTP headers, DNS, cookies, and more.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/report/{token}", response_class=HTMLResponse)
async def serve_report(token: str):
    """Serve report pages — either token-based dynamic reports or legacy static ones."""
    import os, re
    # First check if it's a legacy static report name
    if re.match(r'^[a-zA-Z0-9_-]{1,30}$', token) and not any(c in token for c in '._'):
        path = os.path.join(os.path.dirname(__file__), "static", f"report-{token}.html")
        if os.path.exists(path):
            with open(path, "r") as f:
                return HTMLResponse(content=f.read())
    
    # Try as a token-based report
    token_data = validate_token(token)
    if token_data:
        html_content = generate_report_html(token_data["scan_data"])
        return HTMLResponse(content=html_content)
    
    return HTMLResponse(content="Report not found", status_code=404)

@app.get("/report-demo", response_class=HTMLResponse)
async def report_demo():
    """Redirect old URL."""
    import os
    path = os.path.join(os.path.dirname(__file__), "static", "report-demo.html")
    if os.path.exists(path):
        with open(path, "r") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="Report not found", status_code=404)


class ScanRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith(("http://", "https://")):
            v = f"https://{v}"
        parsed = urlparse(v)
        if not parsed.hostname:
            raise ValueError("Invalid URL")
        return v


class CheckResult(BaseModel):
    id: str
    name: str
    category: str
    status: str  # pass, warn, fail
    description: str
    details: Optional[dict] = None


class ScanResponse(BaseModel):
    url: str
    hostname: str
    score: int
    grade: str
    checks: list[CheckResult]
    scan_time_seconds: float
    total_checks: int
    passed: int
    warnings: int
    failed: int


def compute_score(checks: list[dict]) -> int:
    if not checks:
        return 0
    total = len(checks)
    score = 0
    for c in checks:
        if c["status"] == "pass":
            score += 100
        elif c["status"] == "warn":
            score += 50
    return round(score / total)


def score_to_grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 65:
        return "C"
    if score >= 50:
        return "D"
    return "F"


async def fetch_site(url: str) -> tuple[dict, list, str]:
    """Fetch the target URL and return (headers_dict, set-cookie_list, body)."""
    timeout = aiohttp.ClientTimeout(total=10)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.get(url, allow_redirects=True, ssl=False) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            raw_cookies = resp.headers.getall("set-cookie", [])
            body = await resp.text(errors="replace")
            return headers, raw_cookies, body[:200_000]


@app.post("/scan", response_model=ScanResponse)
async def scan(request: ScanRequest):
    start = time.time()
    url = request.url
    parsed = urlparse(url)
    hostname = parsed.hostname

    # Fetch the site
    try:
        headers, raw_cookies, body = await asyncio.wait_for(fetch_site(url), timeout=15)
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Target site did not respond in time.")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Could not reach target site: {type(e).__name__}: {e}")

    # Run all checks concurrently with overall timeout
    try:
        all_results = await asyncio.wait_for(
            asyncio.gather(
                ssl_tls.run_all(hostname, headers),
                http_headers.run_all(headers),
                dns_records.run_all(hostname),
                server_exposure.run_all(headers),
                cookies.run_all(raw_cookies),
                cms_detection.run_all(body, headers),
                mixed_content.run_all(body, url),
                redirects.run_all(headers, url),
                return_exceptions=True,
            ),
            timeout=25,
        )
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Security checks timed out.")

    # Flatten results
    checks = []
    for result in all_results:
        if isinstance(result, list):
            checks.extend(result)
        elif isinstance(result, Exception):
            checks.append({
                "id": "error",
                "name": "Check Error",
                "category": "Error",
                "status": "fail",
                "description": str(result),
            })

    score = compute_score(checks)
    elapsed = round(time.time() - start, 2)

    passed = sum(1 for c in checks if c["status"] == "pass")
    warnings = sum(1 for c in checks if c["status"] == "warn")
    failed = sum(1 for c in checks if c["status"] == "fail")

    return ScanResponse(
        url=url,
        hostname=hostname,
        score=score,
        grade=score_to_grade(score),
        checks=[CheckResult(**c) for c in checks],
        scan_time_seconds=elapsed,
        total_checks=len(checks),
        passed=passed,
        warnings=warnings,
        failed=failed,
    )


class ReportRequest(BaseModel):
    url: str
    email: str = ""

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v.startswith(("http://", "https://")):
            v = f"https://{v}"
        parsed = urlparse(v)
        if not parsed.hostname:
            raise ValueError("Invalid URL")
        return v


@app.post("/report")
async def report(request: ReportRequest):
    """Run a scan, generate token, and email the report link."""
    if not request.email:
        raise HTTPException(status_code=400, detail="Email is required to receive the report.")

    # Run the scan
    scan_req = ScanRequest(url=request.url)
    scan_result = await scan(scan_req)
    scan_dict = scan_result.model_dump()

    # Generate token and store scan results
    token = generate_token(request.email, scan_dict)

    # Send email with report link
    email_sent = send_report_email(
        to_email=request.email,
        token=token,
        hostname=scan_dict["hostname"],
        score=scan_dict["score"],
        grade=scan_dict["grade"],
    )

    return {
        "status": "success",
        "message": f"Report link sent to {request.email}",
        "email_sent": email_sent,
        "token": token,
        "score": scan_dict["score"],
        "grade": scan_dict["grade"],
    }


@app.post("/report/pdf")
async def report_pdf(request: ReportRequest):
    """Generate a PDF report (legacy/VIP endpoint)."""
    scan_req = ScanRequest(url=request.url)
    scan_result = await scan(scan_req)
    scan_dict = scan_result.model_dump()
    pdf_bytes = generate_pdf(scan_dict)
    hostname = scan_dict["hostname"].replace(".", "_")
    filename = f"webseccheck_{hostname}_report.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


@app.get("/")
async def root():
    return {"status": "ok", "service": "WebSecCheck API", "version": "1.0.0"}


@app.get("/health")
async def health():
    return {"status": "healthy"}
