"""CORS security checks."""

from typing import List, Dict, Any


async def run_all(headers: Dict[str, str]) -> List[Dict[str, Any]]:
    results = []
    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "")

    if acao == "*":
        results.append({
            "id": "cors_wildcard",
            "name": "CORS Wildcard Origin",
            "category": "CORS",
            "status": "warn",
            "description": "Access-Control-Allow-Origin is set to '*'. This allows any site to make requests. Restrict to specific origins.",
            "details": {"value": acao},
        })
    elif acao:
        results.append({
            "id": "cors_wildcard",
            "name": "CORS Wildcard Origin",
            "category": "CORS",
            "status": "pass",
            "description": f"CORS origin is restricted to: {acao}.",
            "details": {"value": acao},
        })
    else:
        results.append({
            "id": "cors_wildcard",
            "name": "CORS Wildcard Origin",
            "category": "CORS",
            "status": "pass",
            "description": "No Access-Control-Allow-Origin header (CORS not enabled, which is secure by default).",
        })

    if acac.lower() == "true" and acao == "*":
        results.append({
            "id": "cors_credentials",
            "name": "CORS with Credentials",
            "category": "CORS",
            "status": "fail",
            "description": "CORS allows credentials with wildcard origin — this is a security risk.",
            "details": {"allow_origin": acao, "allow_credentials": acac},
        })
    elif acac.lower() == "true":
        results.append({
            "id": "cors_credentials",
            "name": "CORS with Credentials",
            "category": "CORS",
            "status": "warn",
            "description": "CORS allows credentials. Ensure the allowed origin is strictly controlled.",
            "details": {"allow_origin": acao, "allow_credentials": acac},
        })
    else:
        results.append({
            "id": "cors_credentials",
            "name": "CORS with Credentials",
            "category": "CORS",
            "status": "pass",
            "description": "CORS credentials are not enabled or properly restricted.",
        })

    return results
