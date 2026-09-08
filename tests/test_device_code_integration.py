"""Integration tests for OIDC device code flow against Docker mockserver.

Requires: docker run --rm -d -p 1080:1080 --name ledger-mock-idp mockserver/mockserver
Run with: pytest tests/test_device_code_integration.py -m integration
"""

from __future__ import annotations

import time

import httpx2 as httpx
import pytest

from traust_ledger.auth import DeviceCodeFlow
from traust_ledger.auth.discovery import discover_oidc

MOCKSERVER_URL = "http://localhost:1080"
ISSUER = f"{MOCKSERVER_URL}/realms/test"
DEVICE_ENDPOINT = f"{MOCKSERVER_URL}/realms/test/protocol/openid-connect/auth/device"
TOKEN_ENDPOINT = f"{MOCKSERVER_URL}/realms/test/protocol/openid-connect/token"
CLIENT_ID = "ledger-cli"


def _mockserver_available() -> bool:
    import time as _time

    for _ in range(10):
        try:
            r = httpx.put(f"{MOCKSERVER_URL}/mockserver/status", timeout=2)
            if r.status_code == 200:
                return True
        except (httpx.ConnectError, httpx.TimeoutException):
            pass
        _time.sleep(1)
    return False


def _setup_expectations() -> None:
    """Configure mockserver expectations for OIDC discovery + device code flow."""
    client = httpx.Client(base_url=MOCKSERVER_URL, timeout=5)

    client.put(
        "/mockserver/expectation",
        json={
            "httpRequest": {
                "method": "GET",
                "path": "/realms/test/.well-known/openid-configuration",
            },
            "httpResponse": {
                "statusCode": 200,
                "headers": {"Content-Type": ["application/json"]},
                "body": {
                    "issuer": ISSUER,
                    "token_endpoint": TOKEN_ENDPOINT,
                    "device_authorization_endpoint": DEVICE_ENDPOINT,
                    "jwks_uri": f"{MOCKSERVER_URL}/realms/test/protocol/openid-connect/certs",
                },
            },
        },
    )

    client.put(
        "/mockserver/expectation",
        json={
            "httpRequest": {
                "method": "POST",
                "path": "/realms/test/protocol/openid-connect/auth/device",
            },
            "httpResponse": {
                "statusCode": 200,
                "headers": {"Content-Type": ["application/json"]},
                "body": {
                    "device_code": "test-device-code",
                    "user_code": "ABCD-EFGH",
                    "verification_uri": f"{MOCKSERVER_URL}/realms/test/device",
                    "interval": 1,
                    "expires_in": 600,
                },
            },
        },
    )

    client.put(
        "/mockserver/expectation",
        json={
            "httpRequest": {
                "method": "POST",
                "path": "/realms/test/protocol/openid-connect/token",
            },
            "httpResponse": {
                "statusCode": 200,
                "headers": {"Content-Type": ["application/json"]},
                "body": {
                    "access_token": "mock-access-token",
                    "refresh_token": "mock-refresh-token",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                },
            },
        },
    )

    client.close()


pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True, scope="module")
def _require_mockserver():
    if not _mockserver_available():
        pytest.skip("mockserver not running — start with: make mock-idp")
    _setup_expectations()


def test_discover_endpoints_from_mockserver() -> None:
    metadata = discover_oidc(ISSUER)
    assert metadata.device_authorization_endpoint == DEVICE_ENDPOINT
    assert metadata.token_endpoint == TOKEN_ENDPOINT


def test_device_login_full_flow(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(time, "sleep", lambda _: None)
    flow = DeviceCodeFlow(ISSUER, CLIENT_ID)
    result = flow.execute()
    assert result["access_token"] == "mock-access-token"
    assert result["refresh_token"] == "mock-refresh-token"
