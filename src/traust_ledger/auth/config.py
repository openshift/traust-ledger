"""Auth configuration — credential resolution and verifier selection.

Two entry points:

  resolve_auth()          — coupled builder for CLI/SDK: resolves a token
                            AND its matching verifier in one step.
  build_verifier_config() — for REST callers with explicit configuration.

See docs/auth.md for the full design.
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import jwt as pyjwt
from traust_contracts.v1.models.layer import LayerActor

from traust_ledger.auth.discovery import discover_oidc
from traust_ledger.auth.local import LOCAL_ISSUER
from traust_ledger.auth.verifier import (
    TokenVerifier,
    TokenVerifierPort,
    VerifierConfig,
)

logger = logging.getLogger(__name__)


class CredentialStore(Protocol):
    """Abstraction over credential persistence (CLI config, env, etc.)."""

    def load_credentials(self) -> dict | None: ...

    def config_dir(self) -> Path: ...


class AuthResolutionError(Exception):
    """No credential or matching verifier could be resolved."""


@dataclass(frozen=True)
class ResolvedCredential:
    """A token and its matching verifier, produced together by the builder."""

    token: str
    verifier: TokenVerifierPort
    source: str

    def verify(self) -> LayerActor:
        """Convenience: verify the bundled token with the paired verifier."""
        return self.verifier.verify(self.token)


# ---------------------------------------------------------------------------
# Coupled builder — CLI / SDK
# ---------------------------------------------------------------------------


def _default_store() -> CredentialStore | None:
    """Lazy-load the CLI credential store. Returns None if CLI extra absent."""
    try:
        from traust_ledger.cli.identity.config import (
            config_dir,
            load_credentials,
        )
    except ImportError:
        return None

    class _CLIStore:
        def load_credentials(self) -> dict | None:
            try:
                return load_credentials()
            except OSError:
                return None

        def config_dir(self) -> Path:
            return config_dir()

    return _CLIStore()


def resolve_auth(
    *,
    store: CredentialStore | None = None,
) -> ResolvedCredential:
    """Resolve a credential and build its matching verifier in one step.

    This is the coupled builder for CLI and SDK callers. The REST service
    receives explicit configuration and does not use this function.

    Pass ``store`` to inject a custom credential store (testing, CI).
    Defaults to the CLI config store when the ``cli`` extra is installed.

    Raises AuthResolutionError if no credential can be resolved.
    """
    # 1. LAAS_TOKEN — env override, always wins
    token = os.environ.get("LAAS_TOKEN", "").strip()
    if token:
        return ResolvedCredential(
            token=token,
            verifier=verifier_for_token(token),
            source="env:LAAS_TOKEN",
        )

    # 2. LEDGER_TOKEN_PATH — file, error if set but unreadable
    token_path = os.environ.get("LEDGER_TOKEN_PATH")
    if token_path:
        try:
            token = Path(token_path).read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise AuthResolutionError(
                f"LEDGER_TOKEN_PATH={token_path} is set but unreadable: {exc}"
            ) from exc
        if token:
            return ResolvedCredential(
                token=token,
                verifier=verifier_for_token(token),
                source="env:LEDGER_TOKEN_PATH",
            )

    # 3. LEDGER_TOKEN — raw env value
    token = os.environ.get("LEDGER_TOKEN", "").strip()
    if token:
        return ResolvedCredential(
            token=token,
            verifier=verifier_for_token(token),
            source="env:LEDGER_TOKEN",
        )

    # Resolve the credential store (CLI or injected)
    _store = store or _default_store()

    # 4. Stored credential — from ledger auth login / local / service-account
    stored = _try_stored_credential(_store)
    if stored is not None:
        return stored

    # 5. Auto-mint — only if LEDGER_LOCAL_IDENTITY is set
    minted = _try_auto_mint(_store)
    if minted is not None:
        return minted

    raise AuthResolutionError(
        "authentication required — set LAAS_TOKEN, or run "
        "`ledger auth login` / `ledger auth local --identity <you>`"
    )


# ---------------------------------------------------------------------------
# Explicit builder — REST service
# ---------------------------------------------------------------------------


def build_verifier_config(
    *,
    jwks_url: str | None = None,
    issuer: str | None = None,
    audience: str | None = None,
    machine_claim: str = "azp",
    identity_claim: str = "email",
) -> VerifierConfig | None:
    """Build a VerifierConfig from explicit args, falling back to env vars.

    For REST callers that pass explicit configuration. CLI/SDK callers
    should use ``resolve_auth()`` instead — it couples token resolution
    with verifier selection.

    Priority: explicit kwargs > LEDGER_OIDC_* env vars > local JWKS file.
    Returns None if no config can be resolved.
    """
    jwks_url = jwks_url or os.environ.get("LEDGER_OIDC_JWKS_URL")
    issuer = issuer or os.environ.get("LEDGER_OIDC_ISSUER")
    audience = audience or os.environ.get("LEDGER_OIDC_AUDIENCE")

    if not issuer and not jwks_url:
        return _local_fallback()

    if not jwks_url and issuer:
        metadata = discover_oidc(issuer)
        jwks_url = metadata.jwks_uri

    return VerifierConfig(
        jwks_url=jwks_url,
        issuer=issuer,
        audience=audience,
        machine_claim=machine_claim,
        identity_claim=identity_claim,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def verifier_for_token(token: str) -> TokenVerifier:
    """Peek ``iss`` to build a matching single-source verifier.

    Used for env-sourced tokens where the credential metadata isn't
    available. The peek is unverified — it only selects the key material,
    and a wrong selection fails at signature check.

    Prefer ``resolve_auth()`` when possible — it pairs token + verifier
    in one step. This is the fallback for callers who already have a token
    but not its verifier (e.g. ``LedgerClient(token)`` without ``from_env``).
    """
    try:
        claims = pyjwt.decode(token, options={"verify_signature": False})
    except pyjwt.InvalidTokenError:
        claims = {}

    issuer = claims.get("iss")
    if issuer == LOCAL_ISSUER:
        return _build_local_verifier()
    return _build_oidc_verifier(issuer=issuer)


def _verifier_for_issuer(issuer: str | None) -> TokenVerifier:
    """Build a single-source verifier for a known issuer."""
    if issuer == LOCAL_ISSUER:
        return _build_local_verifier()
    return _build_oidc_verifier(issuer=issuer)


def _build_local_verifier(
    store: CredentialStore | None = None,
) -> TokenVerifier:
    """Build a verifier that only checks local keys."""
    vc = _local_fallback(store)
    if vc is None:
        raise AuthResolutionError(
            "local token resolved but no local JWKS found — "
            "run `ledger auth local` to generate a keypair"
        )
    return TokenVerifier(vc)


def _build_oidc_verifier(issuer: str | None = None) -> TokenVerifier:
    """Build a verifier that only checks OIDC keys."""
    jwks_url = os.environ.get("LEDGER_OIDC_JWKS_URL")
    oidc_issuer = issuer or os.environ.get("LEDGER_OIDC_ISSUER")
    audience = os.environ.get("LEDGER_OIDC_AUDIENCE")

    if not jwks_url and oidc_issuer:
        metadata = discover_oidc(oidc_issuer)
        jwks_url = metadata.jwks_uri

    if not jwks_url:
        raise AuthResolutionError(
            "OIDC token resolved but no OIDC provider configured — "
            "set LEDGER_OIDC_JWKS_URL or LEDGER_OIDC_ISSUER"
        )

    return TokenVerifier(
        VerifierConfig(
            jwks_url=jwks_url,
            issuer=oidc_issuer,
            audience=audience,
        )
    )


def _try_stored_credential(
    store: CredentialStore | None,
) -> ResolvedCredential | None:
    """Check for a stored credential via the credential store."""
    if store is None:
        return None

    creds = store.load_credentials()
    if not creds or not creds.get("access_token"):
        return None

    expires_at = creds.get("expires_at")
    if expires_at is not None and time.time() >= expires_at:
        return None

    token = creds["access_token"]
    issuer = creds.get("issuer")
    try:
        verifier = _verifier_for_issuer(issuer)
    except AuthResolutionError as exc:
        logger.debug("stored credential skipped: %s", exc)
        return None

    return ResolvedCredential(token=token, verifier=verifier, source="stored")


def _try_auto_mint(
    store: CredentialStore | None,
) -> ResolvedCredential | None:
    """Auto-mint a local token if LEDGER_LOCAL_IDENTITY is set."""
    identity = os.environ.get("LEDGER_LOCAL_IDENTITY", "").strip()
    if not identity:
        return None

    try:
        from traust_ledger.cli.identity.config import _auto_mint_local_token
    except ImportError:
        return None

    try:
        token = _auto_mint_local_token()
    except OSError:
        return None
    if not token:
        return None

    try:
        verifier = _build_local_verifier(store)
    except AuthResolutionError:
        return None

    return ResolvedCredential(token=token, verifier=verifier, source="auto-mint")


def _local_fallback(
    store: CredentialStore | None = None,
) -> VerifierConfig | None:
    """Check for a local JWKS file from ``ledger auth local``."""
    from traust_ledger.auth.local import local_jwks_path

    if store is not None:
        try:
            path = local_jwks_path(store.config_dir())
        except OSError:
            return None
        if path is None:
            return None
        return VerifierConfig(jwks_path=path, issuer=LOCAL_ISSUER)

    # Fallback: try CLI import directly
    try:
        from traust_ledger.cli.identity.config import config_dir
    except ImportError:
        return None

    try:
        path = local_jwks_path(config_dir())
    except OSError:
        return None
    if path is None:
        return None
    return VerifierConfig(jwks_path=path, issuer=LOCAL_ISSUER)
