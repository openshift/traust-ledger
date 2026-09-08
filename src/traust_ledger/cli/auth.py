"""CLI authentication gate — LAAS_TOKEN presence + basic JWT expiry."""

from __future__ import annotations

import base64
import json
import os
import sys
import time

_TOKEN_ENV = "LAAS_TOKEN"


def _decode_jwt_payload(token: str) -> dict | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    payload = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        data = json.loads(base64.urlsafe_b64decode(payload))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _token_expired(token: str) -> bool:
    payload = _decode_jwt_payload(token)
    if payload is None:
        return False
    exp = payload.get("exp")
    if exp is None:
        return False
    try:
        return time.time() >= float(exp)
    except (TypeError, ValueError):
        return True


def require_cli_auth() -> int:
    """Gate CLI commands on LAAS_TOKEN or local/cached credentials.

    Returns 0 when OK, 1 on failure.
    """
    token = os.environ.get(_TOKEN_ENV)
    if token and token.strip():
        if _token_expired(token.strip()):
            print("error: authentication token expired", file=sys.stderr)
            return 1
        return 0

    from traust_ledger.cli.identity.config import resolve_token

    if resolve_token():
        return 0

    print(
        "error: authentication required — set LAAS_TOKEN "
        "or run `ledger auth local --identity you@example.com`",
        file=sys.stderr,
    )
    return 1
