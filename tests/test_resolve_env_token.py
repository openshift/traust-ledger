"""SDK token resolution follows the same chain as `ledger auth token`.

Before `resolve_env_token`, `LedgerClient.from_env()` read `LAAS_TOKEN` and
nothing else. A developer who had run `ledger auth local --identity <them>`
had a valid credential on disk and the SDK still refused to write, reporting
only `authentication required`. Every SDK caller — including traust-engine's
`LedgerService` — inherited that.
"""

from __future__ import annotations

import pytest

from traust_ledger.client import LedgerError, resolve_env_token


def test_laas_token_wins(monkeypatch):
    monkeypatch.setenv("LAAS_TOKEN", "  direct-token  ")
    assert resolve_env_token() == "direct-token"


def test_falls_back_to_cli_chain(monkeypatch):
    """With no LAAS_TOKEN, the CLI's resolution chain is consulted."""
    monkeypatch.delenv("LAAS_TOKEN", raising=False)
    monkeypatch.setattr("traust_ledger.cli.identity.config.resolve_token", lambda: "from-cli-chain")
    assert resolve_env_token() == "from-cli-chain"


def test_token_path_is_honoured(monkeypatch, tmp_path):
    """LEDGER_TOKEN_PATH — the mounted-secret shape — resolves via the chain."""
    monkeypatch.delenv("LAAS_TOKEN", raising=False)
    monkeypatch.delenv("LEDGER_TOKEN", raising=False)
    token_file = tmp_path / "token"
    token_file.write_text("mounted-token\n", encoding="utf-8")
    monkeypatch.setenv("LEDGER_TOKEN_PATH", str(token_file))
    assert resolve_env_token() == "mounted-token"


def test_none_when_nothing_configured(monkeypatch):
    monkeypatch.delenv("LAAS_TOKEN", raising=False)
    monkeypatch.setattr("traust_ledger.cli.identity.config.resolve_token", lambda: None)
    assert resolve_env_token() is None


def test_from_env_error_names_the_remedies(monkeypatch, tmp_path):
    """The failure must say how to get a token, not just that one is absent."""
    monkeypatch.setenv("HOME", str(tmp_path))
    for var in ("LAAS_TOKEN", "LEDGER_TOKEN_PATH", "LEDGER_TOKEN", "LEDGER_LOCAL_IDENTITY"):
        monkeypatch.delenv(var, raising=False)
    for var in ("LEDGER_OIDC_JWKS_URL", "LEDGER_OIDC_ISSUER", "LEDGER_OIDC_AUDIENCE"):
        monkeypatch.delenv(var, raising=False)
    from traust_ledger.client import LedgerClient

    with pytest.raises(LedgerError, match="ledger auth local"):
        LedgerClient.from_env()


def test_unwritable_home_is_not_an_auth_crash(monkeypatch):
    """A credential store we cannot reach is absent, not an exception.

    `resolve_auth` touches the filesystem — `config_dir()` mkdirs on every
    call — so a container, cron job or CI runner with no writable HOME must
    not surface as an OSError. It should fall through to the auth-required
    error.
    """
    monkeypatch.delenv("LAAS_TOKEN", raising=False)
    monkeypatch.delenv("LEDGER_TOKEN_PATH", raising=False)
    monkeypatch.delenv("LEDGER_TOKEN", raising=False)
    monkeypatch.delenv("LEDGER_LOCAL_IDENTITY", raising=False)
    monkeypatch.delenv("LEDGER_OIDC_JWKS_URL", raising=False)
    monkeypatch.delenv("LEDGER_OIDC_ISSUER", raising=False)
    monkeypatch.setenv("HOME", "/nonexistent/readonly")

    from traust_ledger.client import LedgerClient

    with pytest.raises(LedgerError, match="authentication required"):
        LedgerClient.from_env()

    # The legacy resolve_env_token also handles this gracefully
    def _boom():
        raise OSError(30, "Read-only file system")

    monkeypatch.setattr("traust_ledger.cli.identity.config.resolve_token", _boom)
    assert resolve_env_token() is None
