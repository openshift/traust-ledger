"""Service-account token acquisition — the OIDC half of machine identity.

`ledger auth local --machine` covers an operator-run backfill on a trusted host.
This covers the ongoing pipeline, where the same defect applies: a scheduled
emitter with no service account signs as whoever the job runs as.
"""

from __future__ import annotations

import pytest

from traust_ledger.auth.flows import ClientCredentialsFlow
from traust_ledger.auth.flows import client_credentials as cc_module

TOKEN_ENDPOINT = "https://sso.example.com/token"
CLIENT_ID = "harness-triage-emitter"


class _Response:
    def __init__(self, payload, ok=True, status=200):
        self._payload = payload
        self.is_success = ok
        self.status_code = status

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload

    def raise_for_status(self):
        if not self.is_success:
            raise RuntimeError(f"HTTP {self.status_code}")


class _Client:
    def __init__(self, response, sink):
        self._response = response
        self._sink = sink

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def post(self, url, data=None, headers=None):
        self._sink["url"] = url
        self._sink["data"] = data
        return self._response


@pytest.fixture
def http_stub(monkeypatch):
    sink: dict = {}

    def install(response):
        module = type("m", (), {"Client": lambda *a, **k: _Client(response, sink)})
        monkeypatch.setattr(cc_module, "http", lambda: module)
        return sink

    return install


def test_sends_the_client_credentials_grant(http_stub):
    sink = http_stub(_Response({"access_token": "tok", "expires_in": 3600}))
    result = ClientCredentialsFlow(TOKEN_ENDPOINT, CLIENT_ID).execute("s3cret")
    assert result["access_token"] == "tok"
    assert sink["url"] == TOKEN_ENDPOINT
    assert sink["data"]["grant_type"] == "client_credentials"
    assert sink["data"]["client_id"] == CLIENT_ID
    assert sink["data"]["client_secret"] == "s3cret"


def test_empty_secret_refused_before_any_request(http_stub):
    sink = http_stub(_Response({"access_token": "tok"}))
    with pytest.raises(RuntimeError, match="client secret"):
        ClientCredentialsFlow(TOKEN_ENDPOINT, CLIENT_ID).execute("")
    assert sink == {}  # nothing was sent


def test_refusal_surfaces_the_provider_reason(http_stub):
    """An opaque failure is indistinguishable from a typo'd client id."""
    http_stub(
        _Response(
            {"error": "invalid_client", "error_description": "client not enabled"},
            ok=False,
            status=401,
        )
    )
    with pytest.raises(RuntimeError, match="client not enabled"):
        ClientCredentialsFlow(TOKEN_ENDPOINT, CLIENT_ID).execute("s3cret")


def test_non_json_failure_still_raises(http_stub):
    http_stub(_Response(None, ok=False, status=500))
    with pytest.raises(RuntimeError):
        ClientCredentialsFlow(TOKEN_ENDPOINT, CLIENT_ID).execute("s3cret")
