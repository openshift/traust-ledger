"""Refresh token flow — exchange a refresh token for a new access token."""

from __future__ import annotations

from typing import TYPE_CHECKING

from traust_ledger.auth._httpx import http

if TYPE_CHECKING:  # annotations only — no runtime import, no extra required
    import httpx2 as httpx


_REFRESH_TOKEN_ERRORS = frozenset({"invalid_grant", "invalid_token"})


class RefreshFlow:
    """OAuth2 refresh_token grant."""

    def __init__(self, token_endpoint: str, client_id: str) -> None:
        self._token_endpoint = token_endpoint
        self._client_id = client_id

    def execute(self, refresh_token_value: str) -> dict:
        """Exchange refresh token → new token response dict.

        Raises RuntimeError if the refresh token is expired/revoked.
        """
        httpx = http()
        with httpx.Client(timeout=30) as client:
            response = client.post(
                self._token_endpoint,
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token_value,
                    "client_id": self._client_id,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            if response.is_success:
                return response.json()
            _raise_refresh_failed(response)
            return {}  # unreachable, satisfies type checker


def _raise_refresh_failed(response: httpx.Response) -> None:
    try:
        body = response.json()
    except ValueError:
        body = {}
    error = body.get("error", "") if isinstance(body, dict) else ""
    if error in _REFRESH_TOKEN_ERRORS:
        raise RuntimeError("refresh token expired or revoked")
    response.raise_for_status()
