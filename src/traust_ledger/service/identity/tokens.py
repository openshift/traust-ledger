"""Shared bearer token extraction from HTTP requests."""

from __future__ import annotations

from fastapi import Request

from traust_ledger.service.errors import MissingAuthError


def extract_bearer_token(request: Request) -> str:
    authorization = request.headers.get("authorization") or ""
    if not authorization.lower().startswith("bearer "):
        raise MissingAuthError()
    return authorization[7:]
