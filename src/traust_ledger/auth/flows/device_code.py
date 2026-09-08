"""Device code flow — interactive token acquisition for CLI users."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from traust_ledger.auth._httpx import http

if TYPE_CHECKING:  # annotations only — no runtime import, no extra required
    import httpx2 as httpx
from traust_ledger.auth.discovery import discover_oidc

DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"


class DeviceCodeFlow:
    """RFC 8628 device authorization grant."""

    def __init__(self, issuer: str, client_id: str, scope: str = "openid") -> None:
        self._client_id = client_id
        self._scope = scope

        metadata = discover_oidc(issuer)
        if not metadata.device_authorization_endpoint:
            raise RuntimeError("OIDC provider does not publish device_authorization_endpoint")
        self._device_endpoint = metadata.device_authorization_endpoint
        self._token_endpoint = metadata.token_endpoint

    @property
    def token_endpoint(self) -> str:
        return self._token_endpoint

    def execute(self) -> dict:
        """Run the full device-code flow. Returns token response dict.

        Prints verification URI and user code to stdout.
        Polls until user completes auth, or device_code expires.
        """
        httpx = http()
        with httpx.Client(timeout=30) as client:
            device_response = client.post(
                self._device_endpoint,
                data={"client_id": self._client_id, "scope": self._scope},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            device_response.raise_for_status()
            device_data = device_response.json()

            verification_uri = device_data.get("verification_uri") or device_data.get(
                "verification_url"
            )
            user_code = device_data["user_code"]
            device_code = device_data["device_code"]
            interval = device_data.get("interval", 5)

            print(f"Visit {verification_uri} and enter code: {user_code}")

            while True:
                time.sleep(interval)
                try:
                    token_response = client.post(
                        self._token_endpoint,
                        data={
                            "grant_type": DEVICE_CODE_GRANT,
                            "device_code": device_code,
                            "client_id": self._client_id,
                        },
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                    )
                except httpx.TimeoutException as exc:
                    raise RuntimeError("token request timed out") from exc
                except httpx.TransportError as exc:
                    raise RuntimeError(f"token request failed: {exc}") from exc

                if token_response.is_success:
                    return token_response.json()

                error = _oauth_error(token_response)
                if error == "authorization_pending":
                    continue
                if error == "slow_down":
                    interval += 5
                    continue
                if error == "access_denied":
                    raise RuntimeError("authorization denied by user")
                if error == "expired_token":
                    raise RuntimeError("device code expired before authorization completed")
                raise RuntimeError(f"token request failed: {error or token_response.text}")


def _oauth_error(response: httpx.Response) -> str:
    try:
        body = response.json()
    except ValueError:
        return ""
    if isinstance(body, dict):
        return body.get("error", "")
    return ""
