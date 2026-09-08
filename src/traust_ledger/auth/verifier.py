"""JWKS-based JWT verification — the single gate for both CLI and REST.

Each ``TokenVerifier`` is configured with one key source (OIDC *or* local).
The caller — ``resolve_auth()`` in ``config.py`` — picks which source to use
when it resolves the credential, so the verifier never routes internally.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, runtime_checkable

import jwt
from traust_contracts.v1.models.layer import LayerActor

from traust_ledger.auth.claims import TokenVerificationError, claims_to_actor

logger = logging.getLogger(__name__)

_ALGORITHMS = ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]


@runtime_checkable
class TokenVerifierPort(Protocol):
    """Structural protocol satisfied by any object with ``verify(str) → LayerActor``."""

    def verify(self, token: str) -> LayerActor: ...


@dataclass(frozen=True)
class VerifierConfig:
    jwks_url: str | None = None
    jwks_path: Path | None = field(default=None, compare=False)
    issuer: str | None = None
    audience: str | None = None
    machine_claim: str = "azp"
    identity_claim: str = "email"


class TokenVerifier:
    """Cryptographic JWT verification against a single JWKS key source.

    ``resolve_auth()`` builds a ``VerifierConfig`` with one key source
    (OIDC URL *or* local file path). Dual-source configs are rejected.
    """

    def __init__(self, config: VerifierConfig) -> None:
        self._config = config
        self._jwks_client: jwt.PyJWKClient | None = None
        self._local_keys: list[jwt.PyJWK] | None = None

        if config.jwks_path and config.jwks_path.is_file():
            try:
                jwks_data = json.loads(config.jwks_path.read_text(encoding="utf-8"))
                self._local_keys = [jwt.PyJWK(k) for k in jwks_data.get("keys", [])]
            except (json.JSONDecodeError, KeyError, ValueError) as exc:
                logger.warning("corrupt local JWKS at %s: %s", config.jwks_path, exc)
        if config.jwks_url:
            self._jwks_client = jwt.PyJWKClient(config.jwks_url, cache_keys=True)

        if self._local_keys and self._jwks_client:
            raise ValueError(
                "VerifierConfig has both jwks_url and jwks_path — "
                "use resolve_auth() which builds single-source verifiers"
            )

    def verify(self, token: str) -> LayerActor:
        """Verify JWT signature + expiry + claims → LayerActor.

        Raises TokenVerificationError on any failure.
        """
        try:
            signing_key = self._resolve_signing_key(token)

            decode_options: dict[str, object] = {}
            decode_kwargs: dict[str, object] = {
                "key": signing_key,
                "algorithms": _ALGORITHMS,
                "options": decode_options,
            }
            if self._config.issuer:
                decode_kwargs["issuer"] = self._config.issuer
            if self._config.audience:
                decode_kwargs["audience"] = self._config.audience
            else:
                decode_options["verify_aud"] = False

            claims = jwt.decode(token, **decode_kwargs)
        except jwt.ExpiredSignatureError as exc:
            raise TokenVerificationError("token expired") from exc
        except jwt.InvalidIssuerError as exc:
            raise TokenVerificationError("wrong issuer") from exc
        except (jwt.InvalidTokenError, jwt.PyJWKClientError) as exc:
            raise TokenVerificationError(f"invalid token: {exc}") from exc

        return claims_to_actor(
            claims,
            machine_claim=self._config.machine_claim,
            identity_claim=self._config.identity_claim,
            issuer_fallback=self._config.issuer or "",
        )

    def _resolve_signing_key(self, token: str) -> object:
        if self._local_keys:
            return self._local_key_for(token)
        if self._jwks_client is not None:
            return self._jwks_client.get_signing_key_from_jwt(token).key
        raise TokenVerificationError("no JWKS source configured")

    def _local_key_for(self, token: str) -> object:
        assert self._local_keys
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        for k in self._local_keys:
            if kid and k.key_id == kid:
                return k.key
        return self._local_keys[0].key
