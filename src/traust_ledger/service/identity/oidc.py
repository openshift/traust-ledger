"""OIDC JWT identity verifier adapter.

Multi-issuer routing is service-specific; actual verification delegates
to ``TokenVerifier`` instances via the shared ``TokenVerifierPort``.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass

import jwt
from fastapi import Request
from traust_contracts.v1.models.layer import LayerActor

from traust_ledger.auth.verifier import (
    TokenVerificationError,
    TokenVerifier,
    TokenVerifierPort,
    VerifierConfig,
)
from traust_ledger.config import ServiceConfig
from traust_ledger.service.errors import InvalidAuthError
from traust_ledger.service.identity.registry import register
from traust_ledger.service.identity.tokens import extract_bearer_token

logger = logging.getLogger(__name__)


@dataclass
class _TrustEntry:
    """One trusted OIDC issuer with a pre-built verifier."""

    issuer: str | None
    verifier: TokenVerifierPort
    audience: str | None = None


@register("oidc")
class OIDCAdapter:
    """Validates bearer tokens as OIDC JWTs against one or more trusted issuers.

    Each trusted issuer has its own ``TokenVerifier``. A token is validated
    against the entry whose configured issuer matches the token's ``iss``
    claim; when only one entry is configured and it has no issuer set, that
    single entry is used for any token (back-compatible with the previous
    single-issuer behaviour).
    """

    def __init__(self, trust: list[_TrustEntry]) -> None:
        if not trust:
            raise RuntimeError("OIDC adapter requires at least one trusted issuer")
        self._trust = trust
        self._by_issuer = {t.issuer: t for t in trust if t.issuer}
        for entry in trust:
            if not entry.audience:
                logger.warning(
                    "OIDC trust entry for issuer %r started without audience validation — "
                    "tokens issued for other services at the same IdP will be accepted. "
                    "Set an audience to restrict.",
                    entry.issuer or "(any)",
                )

    @classmethod
    def from_config(cls, config: ServiceConfig) -> OIDCAdapter:
        trust: list[_TrustEntry] = []
        raw = (config.oidc_trust or "").strip()
        if raw:
            try:
                items = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise RuntimeError(f"LAAS_OIDC_TRUST is not valid JSON: {exc}") from exc
            if not isinstance(items, list) or not items:
                raise RuntimeError("LAAS_OIDC_TRUST must be a non-empty JSON array")
            for i, item in enumerate(items):
                if not isinstance(item, dict) or not item.get("jwks_url"):
                    raise RuntimeError(f"LAAS_OIDC_TRUST[{i}] must be an object with a jwks_url")
                vc = VerifierConfig(
                    jwks_url=item["jwks_url"],
                    issuer=item.get("issuer"),
                    audience=item.get("audience"),
                    machine_claim=config.oidc_machine_claim,
                    identity_claim=config.oidc_identity_claim,
                )
                trust.append(
                    _TrustEntry(
                        issuer=item.get("issuer"),
                        verifier=TokenVerifier(vc),
                        audience=item.get("audience"),
                    )
                )
            if len(trust) > 1 and any(not t.issuer for t in trust):
                raise RuntimeError(
                    "every LAAS_OIDC_TRUST entry must set 'issuer' when more than one is configured"
                )
        else:
            if not config.oidc_jwks_url:
                raise RuntimeError("identity_provider=oidc requires LAAS_OIDC_JWKS_URL")
            vc = VerifierConfig(
                jwks_url=config.oidc_jwks_url,
                issuer=config.oidc_issuer,
                audience=config.oidc_audience,
                machine_claim=config.oidc_machine_claim,
                identity_claim=config.oidc_identity_claim,
            )
            trust.append(
                _TrustEntry(
                    issuer=config.oidc_issuer,
                    verifier=TokenVerifier(vc),
                    audience=config.oidc_audience,
                )
            )
        return cls(trust)

    def _entry_for_token(self, token: str) -> _TrustEntry:
        """Select the trust entry matching the token's issuer."""
        if len(self._trust) == 1 and self._trust[0].issuer is None:
            return self._trust[0]
        try:
            unverified = jwt.decode(token, options={"verify_signature": False})
        except jwt.InvalidTokenError as exc:
            logger.warning("auth failure reason=undecodable_jwt detail=%s", exc)
            raise InvalidAuthError() from exc
        iss = unverified.get("iss")
        entry = self._by_issuer.get(iss)
        if entry is None:
            logger.warning("auth failure reason=untrusted_issuer iss=%s", iss)
            raise InvalidAuthError()
        return entry

    def verify(self, request: Request) -> LayerActor:
        return self._verify_token(extract_bearer_token(request))

    def _verify_token(self, token: str) -> LayerActor:
        entry = self._entry_for_token(token)
        try:
            return entry.verifier.verify(token)
        except TokenVerificationError as exc:
            msg = str(exc)
            if "expired" in msg:
                logger.warning("auth failure reason=expired_jwt")
            elif "issuer" in msg:
                logger.warning("auth failure reason=wrong_issuer")
            else:
                logger.warning("auth failure reason=invalid_jwt detail=%s", exc)
            raise InvalidAuthError() from exc
