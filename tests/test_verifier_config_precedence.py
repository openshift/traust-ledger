"""Verifier configuration and credential resolution tests.

Tests the two entry points:

  build_verifier_config() — explicit callers (REST service)
  resolve_auth()          — coupled builder (CLI / SDK)

The coupled builder produces a token AND its matching verifier in one step.
The verifier only loads one key source per the builder's decision.
"""

from __future__ import annotations

import json

import pytest

from traust_ledger.auth.config import (
    AuthResolutionError,
    build_verifier_config,
    resolve_auth,
)
from traust_ledger.auth.local import LOCAL_ISSUER, ensure_local_keypair, mint_local_token


@pytest.fixture
def local_auth(tmp_path, monkeypatch):
    """A host where `ledger auth local` has been run."""
    monkeypatch.setenv("HOME", str(tmp_path))
    import time

    from traust_ledger.cli.identity.config import config_dir, save_config, save_credentials

    key = ensure_local_keypair(config_dir())
    token = mint_local_token("triage/1.0", key, machine=True)
    save_config({"active_server": "local", "local_identity": "triage/1.0"})
    save_credentials(
        {"access_token": token, "expires_at": time.time() + 3600, "issuer": "local"},
        host="local",
    )
    return tmp_path


@pytest.fixture
def no_local_auth(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    return tmp_path


def _no_oidc_env(monkeypatch):
    for var in ("LEDGER_OIDC_JWKS_URL", "LEDGER_OIDC_ISSUER", "LEDGER_OIDC_AUDIENCE"):
        monkeypatch.delenv(var, raising=False)


def _no_token_env(monkeypatch):
    for var in ("LAAS_TOKEN", "LEDGER_TOKEN_PATH", "LEDGER_TOKEN", "LEDGER_LOCAL_IDENTITY"):
        monkeypatch.delenv(var, raising=False)


# ---------------------------------------------------------------------------
# build_verifier_config — explicit callers (REST service)
# ---------------------------------------------------------------------------


def test_explicit_oidc_config(monkeypatch):
    _no_oidc_env(monkeypatch)
    config = build_verifier_config(
        jwks_url="https://sso.example.com/certs", issuer="https://sso.example.com"
    )
    assert config is not None
    assert config.jwks_url == "https://sso.example.com/certs"
    assert config.issuer == "https://sso.example.com"
    assert config.jwks_path is None


def test_local_fallback_when_no_oidc(local_auth, monkeypatch):
    _no_oidc_env(monkeypatch)
    config = build_verifier_config()
    assert config is not None and config.issuer == LOCAL_ISSUER


def test_oidc_env_produces_clean_oidc_config(local_auth, monkeypatch):
    """OIDC env → pure OIDC config, no local key material attached."""
    _no_oidc_env(monkeypatch)
    monkeypatch.setenv("LEDGER_OIDC_JWKS_URL", "https://sso.example.com/certs")
    monkeypatch.setenv("LEDGER_OIDC_ISSUER", "https://sso.example.com")
    config = build_verifier_config()
    assert config is not None
    assert config.issuer == "https://sso.example.com"
    assert config.jwks_url == "https://sso.example.com/certs"
    assert config.jwks_path is None


def test_oidc_used_when_local_auth_was_never_chosen(no_local_auth, monkeypatch):
    _no_oidc_env(monkeypatch)
    monkeypatch.setenv("LEDGER_OIDC_JWKS_URL", "https://sso.example.com/certs")
    monkeypatch.setenv("LEDGER_OIDC_ISSUER", "https://sso.example.com")
    config = build_verifier_config()
    assert config is not None
    assert config.jwks_url == "https://sso.example.com/certs"


def test_corrupt_config_does_not_break_resolution(local_auth, monkeypatch):
    _no_oidc_env(monkeypatch)
    from traust_ledger.cli.identity.config import config_dir

    (config_dir() / "config.json").write_text("{ not json", encoding="utf-8")
    monkeypatch.setenv("LEDGER_OIDC_JWKS_URL", "https://sso.example.com/certs")
    config = build_verifier_config()
    assert config is not None and config.jwks_url == "https://sso.example.com/certs"


# ---------------------------------------------------------------------------
# resolve_auth — coupled builder (CLI / SDK)
# ---------------------------------------------------------------------------


def test_resolve_auth_laas_token_wins(local_auth, monkeypatch):
    """LAAS_TOKEN env overrides everything."""
    _no_oidc_env(monkeypatch)
    _no_token_env(monkeypatch)
    key = ensure_local_keypair(local_auth / ".config" / "traust-ledger")
    token = mint_local_token("test@example.com", key)
    monkeypatch.setenv("LAAS_TOKEN", token)
    cred = resolve_auth()
    assert cred.source == "env:LAAS_TOKEN"
    assert cred.token == token


def test_resolve_auth_stored_local_credential(local_auth, monkeypatch):
    """Stored local credential resolves with a local verifier."""
    _no_oidc_env(monkeypatch)
    _no_token_env(monkeypatch)
    cred = resolve_auth()
    assert cred.source == "stored"
    actor = cred.verifier.verify(cred.token)
    assert actor.identity_provider == "local"


def test_resolve_auth_token_path(local_auth, monkeypatch, tmp_path):
    """LEDGER_TOKEN_PATH resolves from file."""
    _no_oidc_env(monkeypatch)
    _no_token_env(monkeypatch)
    key = ensure_local_keypair(local_auth / ".config" / "traust-ledger")
    token = mint_local_token("file@example.com", key)
    token_file = tmp_path / "token"
    token_file.write_text(token, encoding="utf-8")
    monkeypatch.setenv("LEDGER_TOKEN_PATH", str(token_file))
    cred = resolve_auth()
    assert cred.source == "env:LEDGER_TOKEN_PATH"


def test_resolve_auth_token_path_unreadable_is_error(monkeypatch, tmp_path):
    """LEDGER_TOKEN_PATH set but unreadable raises, not silently ignored."""
    _no_token_env(monkeypatch)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("LEDGER_TOKEN_PATH", "/nonexistent/token")
    with pytest.raises(AuthResolutionError, match="LEDGER_TOKEN_PATH"):
        resolve_auth()


def test_resolve_auth_nothing_configured_raises(monkeypatch, tmp_path):
    """No credentials anywhere → clear error naming the remedies."""
    monkeypatch.setenv("HOME", str(tmp_path))
    _no_oidc_env(monkeypatch)
    _no_token_env(monkeypatch)
    with pytest.raises(AuthResolutionError, match="authentication required"):
        resolve_auth()


def test_resolve_auth_auto_mint(monkeypatch, tmp_path):
    """LEDGER_LOCAL_IDENTITY triggers auto-mint with local verifier."""
    monkeypatch.setenv("HOME", str(tmp_path))
    _no_oidc_env(monkeypatch)
    _no_token_env(monkeypatch)
    monkeypatch.setenv("LEDGER_LOCAL_IDENTITY", "auto@example.com")
    cred = resolve_auth()
    assert cred.source == "auto-mint"
    actor = cred.verifier.verify(cred.token)
    assert actor.identity == "auto@example.com"
    assert actor.identity_provider == "local"


def test_resolve_auth_unwritable_home_is_not_a_crash(monkeypatch, tmp_path):
    """Unwritable HOME → auth error, not OSError."""
    _no_token_env(monkeypatch)
    _no_oidc_env(monkeypatch)
    monkeypatch.setenv("HOME", "/nonexistent/readonly")
    with pytest.raises(AuthResolutionError, match="authentication required"):
        resolve_auth()


# ---------------------------------------------------------------------------
# TokenVerifier — single-source and backward-compat dual-source
# ---------------------------------------------------------------------------


def test_local_token_verifies_with_local_verifier(local_auth):
    """Single-source local verifier checks a local token."""
    from traust_ledger.auth.verifier import TokenVerifier, VerifierConfig
    from traust_ledger.cli.identity.config import config_dir
    from traust_ledger.constants import ACTOR_KIND_MACHINE

    key = ensure_local_keypair(config_dir())
    token = mint_local_token("triage/0.32.0", key, machine=True)
    verifier = TokenVerifier(
        VerifierConfig(jwks_path=config_dir() / "local-jwks.json", issuer=LOCAL_ISSUER)
    )
    actor = verifier.verify(token)
    assert actor.kind == ACTOR_KIND_MACHINE
    assert actor.identity == "triage/0.32.0"
    assert actor.identity_provider == "local"


def test_a_forged_local_issuer_does_not_verify(local_auth):
    """Reading `iss` unverified only routes the token; it authorises nothing."""
    import jwt as pyjwt
    from cryptography.hazmat.primitives.asymmetric import ec

    from traust_ledger.auth.verifier import TokenVerificationError, TokenVerifier, VerifierConfig
    from traust_ledger.cli.identity.config import config_dir

    ensure_local_keypair(config_dir())
    attacker_key = ec.generate_private_key(ec.SECP256R1())
    forged = pyjwt.encode(
        {"sub": "root", "azp": "root", "iss": LOCAL_ISSUER},
        attacker_key,
        algorithm="ES256",
        headers={"kid": "local-1"},
    )
    verifier = TokenVerifier(
        VerifierConfig(jwks_path=config_dir() / "local-jwks.json", issuer=LOCAL_ISSUER)
    )
    with pytest.raises(TokenVerificationError):
        verifier.verify(forged)


# ---------------------------------------------------------------------------
# Invariants
# ---------------------------------------------------------------------------


def test_pyjwt_is_a_core_dependency_not_an_extra():
    """It is imported unconditionally on every authenticated write."""
    import tomllib
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    data = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    core = " ".join(data["project"]["dependencies"])
    assert "PyJWT" in core
    for name, deps in data["project"].get("optional-dependencies", {}).items():
        if name == "dev":
            continue
        assert not any("PyJWT" in d for d in deps), (
            f"PyJWT duplicated in the '{name}' extra; it is already a core "
            "dependency and two copies can drift apart"
        )


def test_local_jwks_is_readable_json(local_auth):
    from traust_ledger.cli.identity.config import config_dir

    data = json.loads((config_dir() / "local-jwks.json").read_text(encoding="utf-8"))
    assert data["keys"]
