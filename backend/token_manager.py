"""Token management for WebSecCheck reports — generate, store, validate tokens linked to scan results."""

import json
import os
import secrets
import time
from typing import Optional

TOKENS_FILE = os.path.join(os.path.dirname(__file__), "data", "tokens.json")


def _ensure_data_dir():
    os.makedirs(os.path.dirname(TOKENS_FILE), exist_ok=True)
    if not os.path.exists(TOKENS_FILE):
        with open(TOKENS_FILE, "w") as f:
            json.dump({}, f)


def _load_tokens() -> dict:
    _ensure_data_dir()
    with open(TOKENS_FILE, "r") as f:
        return json.load(f)


def _save_tokens(tokens: dict):
    _ensure_data_dir()
    with open(TOKENS_FILE, "w") as f:
        json.dump(tokens, f, indent=2)


def generate_token(email: str, scan_data: dict) -> str:
    """Generate a unique token and store it linked to scan results."""
    token = secrets.token_urlsafe(32)
    tokens = _load_tokens()
    tokens[token] = {
        "email": email,
        "scan_data": scan_data,
        "created_at": time.time(),
        "views": 0,
    }
    _save_tokens(tokens)
    return token


def validate_token(token: str) -> Optional[dict]:
    """Validate token and return scan data if valid. Increments view count."""
    tokens = _load_tokens()
    if token not in tokens:
        return None
    tokens[token]["views"] += 1
    _save_tokens(tokens)
    return tokens[token]
