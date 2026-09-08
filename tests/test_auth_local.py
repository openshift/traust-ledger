"""Tests for ledger auth local — local identity gate."""

from __future__ import annotations

import json
from pathlib import Path
from unittest import mock

import jwt
import pytest
from traust_contracts.v1.models.layer import LayerActor

from traust_ledger.auth.local import (
    LOCAL_ISSUER,
    ensure_local_keypair,
    local_jwks_path,
    mint_local_token,
)
from traust_ledger.auth.verifier import TokenVerifier, VerifierConfig


@pytest.fixture()
def local_config_dir(tmp_path: Path) -> Path:
    d = tmp_path / "traust-ledger"
    d.mkdir()
    return d


class TestEnsureLocalKeypair:
    def test_generates_key_and_jwks(self, local_config_dir: Path) -> None:
        key = ensure_local_keypair(local_config_dir)
        assert (local_config_dir / "local-key.pem").is_file()
        assert (local_config_dir / "local-jwks.json").is_file()

        jwks = json.loads((local_config_dir / "local-jwks.json").read_text())
        assert "keys" in jwks
        assert len(jwks["keys"]) == 1
        assert jwks["keys"][0]["kty"] == "EC"
        assert jwks["keys"][0]["kid"] == "local-1"
        assert key is not None

    def test_reuses_existing_key(self, local_config_dir: Path) -> None:
        key1 = ensure_local_keypair(local_config_dir)
        key2 = ensure_local_keypair(local_config_dir)
        n1 = key1.private_numbers()
        n2 = key2.private_numbers()
        assert n1.private_value == n2.private_value

    def test_regenerates_jwks_if_missing(self, local_config_dir: Path) -> None:
        ensure_local_keypair(local_config_dir)
        (local_config_dir / "local-jwks.json").unlink()
        ensure_local_keypair(local_config_dir)
        assert (local_config_dir / "local-jwks.json").is_file()

    def test_creates_config_dir(self, tmp_path: Path) -> None:
        d = tmp_path / "nonexistent" / "dir"
        ensure_local_keypair(d)
        assert d.is_dir()
        assert (d / "local-key.pem").is_file()


class TestMintLocalToken:
    def test_token_decodes(self, local_config_dir: Path) -> None:
        key = ensure_local_keypair(local_config_dir)
        token = mint_local_token("alice@corp.com", key)
        opts = {"verify_aud": False}
        claims = jwt.decode(token, key.public_key(), algorithms=["ES256"], options=opts)
        assert claims["sub"] == "alice@corp.com"
        assert claims["email"] == "alice@corp.com"
        assert claims["iss"] == "local"
        assert "exp" in claims
        assert "iat" in claims

    def test_token_has_kid_header(self, local_config_dir: Path) -> None:
        key = ensure_local_keypair(local_config_dir)
        token = mint_local_token("alice@corp.com", key)
        header = jwt.get_unverified_header(token)
        assert header["kid"] == "local-1"

    def test_token_expiry(self, local_config_dir: Path) -> None:
        key = ensure_local_keypair(local_config_dir)
        token = mint_local_token("alice@corp.com", key)
        opts = {"verify_aud": False}
        claims = jwt.decode(token, key.public_key(), algorithms=["ES256"], options=opts)
        assert claims["exp"] - claims["iat"] == 7 * 24 * 3600


class TestLocalJwksPath:
    def test_returns_path_when_exists(self, local_config_dir: Path) -> None:
        ensure_local_keypair(local_config_dir)
        assert local_jwks_path(local_config_dir) is not None

    def test_returns_none_when_missing(self, tmp_path: Path) -> None:
        assert local_jwks_path(tmp_path) is None


class TestLocalRoundTrip:
    """Mint a local token, then verify it with TokenVerifier using jwks_path."""

    def test_verify_local_token(self, local_config_dir: Path) -> None:
        key = ensure_local_keypair(local_config_dir)
        token = mint_local_token("alice@corp.com", key)

        jwks_path = local_jwks_path(local_config_dir)
        config = VerifierConfig(jwks_path=jwks_path, issuer=LOCAL_ISSUER)
        verifier = TokenVerifier(config)
        actor = verifier.verify(token)

        assert isinstance(actor, LayerActor)
        assert actor.identity == "alice@corp.com"
        assert actor.kind == "human"
        assert actor.identity_verified is True
        assert actor.identity_provider == "local"
        assert actor.identity_issuer == "local"


class TestLocalActorWithGates:
    """Local actors should pass all domain gates."""

    def _make_local_actor(self) -> LayerActor:
        return LayerActor(
            kind="human",
            identity="alice@corp.com",
            identity_verified=True,
            identity_provider="local",
            identity_issuer="local",
        )

    def test_require_human_identity_passes(self) -> None:
        from traust_ledger._internal.gates import require_human_identity
        from traust_ledger._internal.kinds import EventKind

        actor = self._make_local_actor()
        require_human_identity(actor, EventKind.COUNTERSIGN)

    def test_require_verified_for_false_positive_passes(self) -> None:
        from traust_ledger._internal.gates import require_verified_for_false_positive

        actor = self._make_local_actor()
        require_verified_for_false_positive(actor, "false_positive")


class TestResolveTokenLocalFallback:
    """LEDGER_LOCAL_IDENTITY env var auto-mints a local token."""

    def test_env_auto_mint(self, local_config_dir: Path) -> None:
        from traust_ledger.cli.identity.config import resolve_token

        env = {
            "LEDGER_LOCAL_IDENTITY": "bob@example.com",
        }
        with (
            mock.patch.dict("os.environ", env, clear=False),
            mock.patch(
                "traust_ledger.cli.identity.config.config_dir",
                return_value=local_config_dir,
            ),
            mock.patch(
                "traust_ledger.cli.identity.config.load_credentials",
                return_value=None,
            ),
        ):
            token = resolve_token()

        assert token is not None
        claims = jwt.decode(
            token,
            options={"verify_signature": False, "verify_aud": False},
        )
        assert claims["email"] == "bob@example.com"
        assert claims["iss"] == "local"

    def test_env_not_set_returns_none(self) -> None:
        from traust_ledger.cli.identity.config import resolve_token

        cleared = {
            "LEDGER_TOKEN_PATH": "",
            "LEDGER_TOKEN": "",
            "LEDGER_LOCAL_IDENTITY": "",
        }
        with (
            mock.patch.dict("os.environ", cleared, clear=False),
            mock.patch(
                "traust_ledger.cli.identity.config.load_credentials",
                return_value=None,
            ),
        ):
            token = resolve_token()

        assert token is None


class TestLedgerClientActorGate:
    """LedgerClient._actor() must verify-or-refuse, matching CLI and REST."""

    def test_rejects_garbage_token_without_auth_config(self, tmp_path: Path) -> None:
        """No OIDC env, no local JWKS → LedgerError, not a hollow actor."""
        from traust_ledger.client import LedgerClient, LedgerError

        empty_dir = tmp_path / "empty-config"
        empty_dir.mkdir()
        cleared = {
            "LEDGER_OIDC_ISSUER": "",
            "LEDGER_OIDC_JWKS_URL": "",
            "LEDGER_OIDC_AUDIENCE": "",
        }
        with (
            mock.patch.dict("os.environ", cleared, clear=False),
            mock.patch(
                "traust_ledger.cli.identity.config.config_dir",
                return_value=empty_dir,
            ),
            pytest.raises(LedgerError, match=r"OIDC|identity verification"),
        ):
            client = LedgerClient("garbage-not-a-jwt", data_dir=str(tmp_path))
            client._actor()

    def test_accepts_valid_local_token(self, local_config_dir: Path) -> None:
        """Local auth round-trip: mint → client._actor() → verified actor."""
        from traust_ledger.auth.local import ensure_local_keypair, mint_local_token
        from traust_ledger.client import LedgerClient

        key = ensure_local_keypair(local_config_dir)
        token = mint_local_token("alice@corp.com", key)

        cleared = {
            "LEDGER_OIDC_ISSUER": "",
            "LEDGER_OIDC_JWKS_URL": "",
            "LEDGER_OIDC_AUDIENCE": "",
        }
        with (
            mock.patch.dict("os.environ", cleared, clear=False),
            mock.patch(
                "traust_ledger.cli.identity.config.config_dir",
                return_value=local_config_dir,
            ),
        ):
            client = LedgerClient(token, data_dir=str(local_config_dir))
            actor = client._actor()

        assert actor.identity == "alice@corp.com"
        assert actor.identity_verified is True
        assert actor.kind == "human"

    def test_rejects_expired_local_token(self, local_config_dir: Path) -> None:
        """Expired token → LedgerError, not silent degradation."""
        from traust_ledger.auth.local import LOCAL_ISSUER, ensure_local_keypair
        from traust_ledger.client import LedgerClient, LedgerError

        key = ensure_local_keypair(local_config_dir)
        expired = jwt.encode(
            {
                "sub": "alice@corp.com",
                "email": "alice@corp.com",
                "iss": LOCAL_ISSUER,
                "iat": 0,
                "exp": 1,
            },
            key,
            algorithm="ES256",
            headers={"kid": "local-1"},
        )
        cleared = {
            "LEDGER_OIDC_ISSUER": "",
            "LEDGER_OIDC_JWKS_URL": "",
            "LEDGER_OIDC_AUDIENCE": "",
        }
        with (
            mock.patch.dict("os.environ", cleared, clear=False),
            mock.patch(
                "traust_ledger.cli.identity.config.config_dir",
                return_value=local_config_dir,
            ),
            pytest.raises(LedgerError, match="token verification failed"),
        ):
            client = LedgerClient(expired, data_dir=str(local_config_dir))
            client._actor()


class TestRememberedIdentity:
    """ledger auth local saves identity to config for subsequent runs."""

    def test_first_run_saves_identity(self, local_config_dir: Path) -> None:
        import argparse

        from traust_ledger.cli.identity.commands import cmd_auth_local

        with (
            mock.patch(
                "traust_ledger.cli.identity.commands.load_config",
                return_value={},
            ),
            mock.patch(
                "traust_ledger.cli.identity.commands.save_config",
            ) as mock_save_config,
            mock.patch(
                "traust_ledger.cli.identity.commands.save_credentials",
            ) as mock_save_creds,
            mock.patch(
                "traust_ledger.cli.identity.config.config_dir",
                return_value=local_config_dir,
            ),
        ):
            args = argparse.Namespace(identity="Alice@Corp.com")
            rc = cmd_auth_local(args)

        assert rc == 0
        saved_config = mock_save_config.call_args[0][0]
        assert saved_config["local_identity"] == "alice@corp.com"
        assert saved_config["active_server"] == "local"

        saved_creds = mock_save_creds.call_args[0][0]
        assert "access_token" in saved_creds
        assert saved_creds["issuer"] == "local"

    def test_second_run_reads_identity(self, local_config_dir: Path) -> None:
        import argparse

        from traust_ledger.cli.identity.commands import cmd_auth_local

        with (
            mock.patch(
                "traust_ledger.cli.identity.commands.load_config",
                return_value={"local_identity": "alice@corp.com"},
            ),
            mock.patch("traust_ledger.cli.identity.commands.save_config"),
            mock.patch("traust_ledger.cli.identity.commands.save_credentials"),
            mock.patch(
                "traust_ledger.cli.identity.config.config_dir",
                return_value=local_config_dir,
            ),
        ):
            args = argparse.Namespace(identity=None)
            rc = cmd_auth_local(args)

        assert rc == 0

    def test_no_identity_fails(self, local_config_dir: Path) -> None:
        import argparse

        from traust_ledger.cli.identity.commands import cmd_auth_local

        with mock.patch(
            "traust_ledger.cli.identity.commands.load_config",
            return_value={},
        ):
            args = argparse.Namespace(identity=None)
            rc = cmd_auth_local(args)

        assert rc == 1
