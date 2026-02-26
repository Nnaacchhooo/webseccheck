# WebSecCheck Backend

Passive web security scanner API built with FastAPI.

## Checks (18 total)

### SSL/TLS (4)
- Certificate validity
- Certificate expiration
- TLS protocol version
- HSTS header

### HTTP Headers (5)
- Content Security Policy
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy

### DNS (3)
- SPF record
- DKIM record
- DMARC record

### Server Exposure (2)
- Server version disclosure
- X-Powered-By leak

### Cookies (1)
- Secure/HttpOnly/SameSite flags

### CMS Detection (1)
- WordPress/Drupal/Joomla version exposure

## API

```
POST /scan
Body: { "url": "https://example.com" }
```

Returns: score (0-100), grade (A-F), per-check results with pass/warn/fail status.

## Deploy on HuggingFace Spaces

1. Create a new Space with Docker SDK
2. Upload the backend files
3. The Dockerfile exposes port 7860 (HF Spaces default)

## Local Development

```bash
pip install -r requirements.txt
uvicorn app:app --reload --port 7860
```
