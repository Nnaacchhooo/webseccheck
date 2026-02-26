"""WebSecCheck - Basic version that works."""

import asyncio
import time
from typing import Optional
from urllib.parse import urlparse

import aiohttp
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator

# Import only working checks
from checks import ssl_tls, http_headers, dns_records, server_exposure, cookies, cms_detection

app = FastAPI(
    title="WebSecCheck API",
    description="Basic web security scanner",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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
    status: str
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
    timeout = aiohttp.ClientTimeout(total=10)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.get(url, allow_redirects=True, ssl=False) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            raw_cookies = resp.headers.getall("set-cookie", [])
            body = await resp.text(errors="replace")
            return headers, raw_cookies, body[:50000]  # Smaller body


@app.post("/scan", response_model=ScanResponse)
async def scan(request: ScanRequest):
    start = time.time()
    url = request.url
    parsed = urlparse(url)
    hostname = parsed.hostname

    try:
        headers, raw_cookies, body = await asyncio.wait_for(fetch_site(url), timeout=15)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Could not reach target site: {e}")

    # Run basic checks only
    try:
        all_results = await asyncio.wait_for(
            asyncio.gather(
                ssl_tls.run_all(hostname, headers),
                http_headers.run_all(headers),
                dns_records.run_all(hostname),
                server_exposure.run_all(headers),
                cookies.run_all(raw_cookies),
                cms_detection.run_all(body, headers),
                return_exceptions=True,
            ),
            timeout=25,
        )
    except Exception as e:
        raise HTTPException(status_code=504, detail=f"Checks failed: {e}")

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


@app.get("/")
async def root():
    return {"status": "ok", "service": "WebSecCheck API Basic"}


@app.get("/health")
async def health():
    return {"status": "healthy"}