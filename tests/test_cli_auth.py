"""Tests for ledger CLI auth, client, and fingerprint command."""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

import httpx2 as httpx
import pytest

from traust_ledger._internal.identity import fingerprint
from traust_ledger.auth import DeviceCodeFlow
from traust_ledger.auth.discovery import discover_oidc
from traust_ledger.auth.flows.refresh import RefreshFlow
from traust_ledger.cli.commands.fingerprint import cmd_fingerprint
from traust_ledger.cli.identity import config as auth_config


def _patch_config_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    cfg_dir = tmp_path / "ledger"
    monkeypatch.setattr(auth_config, "config_dir", lambda: cfg_dir)
    return cfg_dir


class _FakeResponse:
    def __init__(
        self,
        *,
        status_code: int = 200,
        json_data: dict[str, Any] | None = None,
        text: str = "",
    ) -> None:
        self.status_code = status_code
        self._json = json_data or {}
        self.text = text

    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 300

    def raise_for_status(self) -> None:
        if not self.is_success:
            request = httpx.Request("GET", "http://test")
            response = httpx.Response(self.status_code, request=request, text=self.text)
            raise httpx.HTTPStatusError("error", request=request, response=response)

    def json(self) -> dict[str, Any]:
        return self._json


class _FakeHttpxClient:
    def __init__(self, *, get_handler=None, post_handler=None, timeout=None) -> None:
        self._get_handler = get_handler
        self._post_handler = post_handler

    def get(self, url: str, **kwargs: Any) -> _FakeResponse:
        if self._get_handler is not None:
            return self._get_handler(url, **kwargs)
        raise AssertionError(f"unexpected GET {url}")

    def post(self, url: str, **kwargs: Any) -> _FakeResponse:
        if self._post_handler is not None:
            return self._post_handler(url, **kwargs)
        raise AssertionError(f"unexpected POST {url}")

    def request(self, method: str, url: str, **kwargs: Any) -> _FakeResponse:
        if method.upper() == "GET":
            return self.get(url, **kwargs)
        if method.upper() == "POST":
            return self.post(url, **kwargs)
        raise AssertionError(f"unexpected {method} {url}")

    def __enter__(self) -> _FakeHttpxClient:
        return self

    def __exit__(self, *args: Any) -> None:
        return None


def test_config_dir_creates_with_correct_permissions(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    cfg_root = tmp_path / "config-root"
    monkeypatch.setattr(
        Path,
        "home",
        classmethod(lambda cls: cfg_root),
    )
    path = auth_config.config_dir()
    assert path.is_dir()
    assert (path.stat().st_mode & 0o777) == 0o700


def test_save_and_load_credentials(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _patch_config_dir(monkeypatch, tmp_path)
    monkeypatch.setenv("LEDGER_SERVER_URL", "https://test-host")
    data = {"access_token": "abc", "refresh_token": "def", "expires_at": 9999999999}
    auth_config.save_credentials(data)
    loaded = auth_config.load_credentials()
    assert loaded == data


def test_credentials_file_permissions(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cfg_dir = _patch_config_dir(monkeypatch, tmp_path)
    monkeypatch.setenv("LEDGER_SERVER_URL", "https://test-host")
    auth_config.save_credentials({"access_token": "abc"})
    cred_path = cfg_dir / "credentials.json"
    assert cred_path.is_file()
    assert (cred_path.stat().st_mode & 0o777) == 0o600


def test_clear_credentials(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    cfg_dir = _patch_config_dir(monkeypatch, tmp_path)
    monkeypatch.setenv("LEDGER_SERVER_URL", "https://test-host")
    auth_config.save_credentials({"access_token": "abc"})
    cred_path = cfg_dir / "credentials.json"
    assert cred_path.is_file()
    auth_config.clear_credentials(host="https://test-host")
    assert not cred_path.exists()


def test_resolve_token_from_env_token_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _patch_config_dir(monkeypatch, tmp_path)
    token_file = tmp_path / "token.txt"
    token_file.write_text("path-token\n", encoding="utf-8")
    monkeypatch.setenv("LEDGER_TOKEN_PATH", str(token_file))
    monkeypatch.delenv("LEDGER_TOKEN", raising=False)
    assert auth_config.resolve_token() == "path-token"


def test_resolve_token_from_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _patch_config_dir(monkeypatch, tmp_path)
    monkeypatch.delenv("LEDGER_TOKEN_PATH", raising=False)
    monkeypatch.setenv("LEDGER_TOKEN", "static-token")
    assert auth_config.resolve_token() == "static-token"


def test_resolve_token_from_credentials(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _patch_config_dir(monkeypatch, tmp_path)
    monkeypatch.delenv("LEDGER_TOKEN_PATH", raising=False)
    monkeypatch.delenv("LEDGER_TOKEN", raising=False)
    monkeypatch.setenv("LEDGER_SERVER_URL", "https://test-host")
    auth_config.save_credentials(
        {"access_token": "cred-token", "expires_at": time.time() + 3600},
    )
    assert auth_config.resolve_token() == "cred-token"


def test_resolve_token_expired_credentials(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _patch_config_dir(monkeypatch, tmp_path)
    monkeypatch.delenv("LEDGER_TOKEN_PATH", raising=False)
    monkeypatch.delenv("LEDGER_TOKEN", raising=False)
    monkeypatch.setenv("LEDGER_SERVER_URL", "https://test-host")
    auth_config.save_credentials(
        {"access_token": "expired-token", "expires_at": time.time() - 60},
    )
    assert auth_config.resolve_token() is None


def test_resolve_token_priority_order(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _patch_config_dir(monkeypatch, tmp_path)
    token_file = tmp_path / "token.txt"
    token_file.write_text("path-token", encoding="utf-8")
    monkeypatch.setenv("LEDGER_TOKEN_PATH", str(token_file))
    monkeypatch.setenv("LEDGER_TOKEN", "static-token")
    monkeypatch.setenv("LEDGER_SERVER_URL", "https://test-host")
    auth_config.save_credentials(
        {"access_token": "cred-token", "expires_at": time.time() + 3600},
    )
    assert auth_config.resolve_token() == "path-token"

    monkeypatch.delenv("LEDGER_TOKEN_PATH", raising=False)
    assert auth_config.resolve_token() == "static-token"

    monkeypatch.delenv("LEDGER_TOKEN", raising=False)
    assert auth_config.resolve_token() == "cred-token"


def test_discover_endpoints(monkeypatch: pytest.MonkeyPatch) -> None:
    def get_handler(url: str, **kwargs: Any) -> _FakeResponse:
        assert url.endswith("/.well-known/openid-configuration")
        return _FakeResponse(
            json_data={
                "jwks_uri": "https://issuer/jwks",
                "device_authorization_endpoint": "https://issuer/device",
                "token_endpoint": "https://issuer/token",
            },
        )

    monkeypatch.setattr(
        httpx,
        "Client",
        lambda timeout=30: _FakeHttpxClient(get_handler=get_handler),
    )
    metadata = discover_oidc("https://issuer")
    assert metadata.device_authorization_endpoint == "https://issuer/device"
    assert metadata.token_endpoint == "https://issuer/token"


def test_discover_endpoints_missing_device_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    def get_handler(url: str, **kwargs: Any) -> _FakeResponse:
        return _FakeResponse(
            json_data={
                "jwks_uri": "https://issuer/jwks",
                "token_endpoint": "https://issuer/token",
            },
        )

    monkeypatch.setattr(
        httpx,
        "Client",
        lambda timeout=30: _FakeHttpxClient(get_handler=get_handler),
    )
    with pytest.raises(RuntimeError, match="device_authorization_endpoint"):
        DeviceCodeFlow("https://issuer", "client-id")


def test_device_login_success(monkeypatch: pytest.MonkeyPatch) -> None:
    poll_count = 0

    def get_handler(url: str, **kwargs: Any) -> _FakeResponse:
        return _FakeResponse(
            json_data={
                "jwks_uri": "https://issuer/jwks",
                "device_authorization_endpoint": "https://issuer/device",
                "token_endpoint": "https://issuer/token",
            },
        )

    def post_handler(url: str, **kwargs: Any) -> _FakeResponse:
        if url == "https://issuer/device":
            return _FakeResponse(
                json_data={
                    "verification_uri": "https://issuer/verify",
                    "user_code": "ABCD",
                    "device_code": "device-code",
                    "interval": 0,
                },
            )
        nonlocal poll_count
        poll_count += 1
        if poll_count == 1:
            return _FakeResponse(status_code=400, json_data={"error": "authorization_pending"})
        return _FakeResponse(
            json_data={"access_token": "new-access", "refresh_token": "new-refresh"},
        )

    monkeypatch.setattr(
        httpx,
        "Client",
        lambda timeout=30: _FakeHttpxClient(get_handler=get_handler, post_handler=post_handler),
    )
    monkeypatch.setattr(time, "sleep", lambda _: None)

    flow = DeviceCodeFlow("https://issuer", "client-id")
    result = flow.execute()
    assert result == {"access_token": "new-access", "refresh_token": "new-refresh"}
    assert poll_count == 2


def test_device_login_slow_down(monkeypatch: pytest.MonkeyPatch) -> None:
    poll_count = 0
    sleep_intervals: list[float] = []

    def get_handler(url: str, **kwargs: Any) -> _FakeResponse:
        return _FakeResponse(
            json_data={
                "jwks_uri": "https://issuer/jwks",
                "device_authorization_endpoint": "https://issuer/device",
                "token_endpoint": "https://issuer/token",
            },
        )

    def post_handler(url: str, **kwargs: Any) -> _FakeResponse:
        if url == "https://issuer/device":
            return _FakeResponse(
                json_data={
                    "verification_uri": "https://issuer/verify",
                    "user_code": "ABCD",
                    "device_code": "device-code",
                    "interval": 5,
                },
            )
        nonlocal poll_count
        poll_count += 1
        if poll_count == 1:
            return _FakeResponse(status_code=400, json_data={"error": "slow_down"})
        return _FakeResponse(json_data={"access_token": "token"})

    monkeypatch.setattr(
        httpx,
        "Client",
        lambda timeout=30: _FakeHttpxClient(get_handler=get_handler, post_handler=post_handler),
    )
    monkeypatch.setattr(time, "sleep", lambda interval: sleep_intervals.append(interval))

    flow = DeviceCodeFlow("https://issuer", "client-id")
    flow.execute()
    assert sleep_intervals == [5, 10]


def test_device_login_access_denied(monkeypatch: pytest.MonkeyPatch) -> None:
    def get_handler(url: str, **kwargs: Any) -> _FakeResponse:
        return _FakeResponse(
            json_data={
                "jwks_uri": "https://issuer/jwks",
                "device_authorization_endpoint": "https://issuer/device",
                "token_endpoint": "https://issuer/token",
            },
        )

    def post_handler(url: str, **kwargs: Any) -> _FakeResponse:
        if url == "https://issuer/device":
            return _FakeResponse(
                json_data={
                    "verification_uri": "https://issuer/verify",
                    "user_code": "ABCD",
                    "device_code": "device-code",
                    "interval": 0,
                },
            )
        return _FakeResponse(status_code=400, json_data={"error": "access_denied"})

    monkeypatch.setattr(
        httpx,
        "Client",
        lambda timeout=30: _FakeHttpxClient(get_handler=get_handler, post_handler=post_handler),
    )
    monkeypatch.setattr(time, "sleep", lambda _: None)

    flow = DeviceCodeFlow("https://issuer", "client-id")
    with pytest.raises(RuntimeError, match="authorization denied"):
        flow.execute()


def test_refresh_token_success(monkeypatch: pytest.MonkeyPatch) -> None:
    def post_handler(url: str, **kwargs: Any) -> _FakeResponse:
        assert url == "https://issuer/token"
        assert kwargs["data"]["grant_type"] == "refresh_token"
        return _FakeResponse(
            json_data={"access_token": "refreshed", "refresh_token": "refreshed-refresh"},
        )

    monkeypatch.setattr(
        httpx,
        "Client",
        lambda timeout=30: _FakeHttpxClient(post_handler=post_handler),
    )
    flow = RefreshFlow("https://issuer/token", "client-id")
    result = flow.execute("old-refresh")
    assert result == {"access_token": "refreshed", "refresh_token": "refreshed-refresh"}


def test_refresh_token_expired(monkeypatch: pytest.MonkeyPatch) -> None:
    def post_handler(url: str, **kwargs: Any) -> _FakeResponse:
        return _FakeResponse(status_code=400, json_data={"error": "invalid_grant"})

    monkeypatch.setattr(
        httpx,
        "Client",
        lambda timeout=30: _FakeHttpxClient(post_handler=post_handler),
    )
    flow = RefreshFlow("https://issuer/token", "client-id")
    with pytest.raises(RuntimeError, match="expired or revoked"):
        flow.execute("old-refresh")


def test_load_credentials_ignores_malformed_json(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    cfg_dir = _patch_config_dir(monkeypatch, tmp_path)
    cfg_dir.mkdir(parents=True, exist_ok=True)
    (cfg_dir / "credentials.json").write_text("{not json", encoding="utf-8")
    assert auth_config.load_credentials() is None


def test_resolve_token_missing_token_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _patch_config_dir(monkeypatch, tmp_path)
    monkeypatch.setenv("LEDGER_TOKEN_PATH", str(tmp_path / "missing-token.txt"))
    monkeypatch.delenv("LEDGER_TOKEN", raising=False)
    with pytest.raises(RuntimeError, match=r"LEDGER_TOKEN_PATH.*unreadable"):
        auth_config.resolve_token()


def test_fingerprint_stamps_findings(tmp_path: Path) -> None:
    finding = {
        "locations": [{"path": "src/main.py"}],
        "cwes": ["CWE-79"],
    }
    repo_url = "https://github.com/org/repo"
    expected_fp = fingerprint(finding, repo_url)
    report = {
        "metadata": {"repository": repo_url},
        "findings": [finding],
    }
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")

    result = cmd_fingerprint(argparse.Namespace(report_path=str(report_path)))
    assert result == 0

    updated = json.loads(report_path.read_text(encoding="utf-8"))
    stamped = updated["findings"][0]
    assert stamped["fingerprint"] == expected_fp
