"""JWT claims → LayerActor mapping.

Shared by all verifier implementations (OIDC, local, REST adapter).
The mapping is by claim shape alone — the verifier is responsible for
cryptographic verification before calling this.
"""

from __future__ import annotations

from traust_contracts.v1.models.layer import LayerActor

from traust_ledger.auth.local import LOCAL_ISSUER
from traust_ledger.constants import ACTOR_KIND_HUMAN, ACTOR_KIND_MACHINE


class TokenVerificationError(Exception):
    """Raised when a token fails cryptographic or claims verification."""


class IdentityClaimsError(TokenVerificationError):
    """Claims are valid JWT but cannot be mapped to an actor identity."""


def claims_to_actor(
    claims: dict[str, object],
    *,
    machine_claim: str = "azp",
    identity_claim: str = "email",
    issuer_fallback: str = "",
) -> LayerActor:
    """Map verified JWT claims to a ``LayerActor``.

    Raises ``TokenVerificationError`` if no identity can be derived.
    """
    machine_value = claims.get(machine_claim)
    identity_value = claims.get(identity_claim)

    if machine_value and not identity_value:
        kind = ACTOR_KIND_MACHINE
        identity = str(machine_value)
    elif identity_value:
        stripped = str(identity_value).lower().strip()
        if not stripped:
            raise IdentityClaimsError(f"empty identity claim: {identity_claim}")
        kind = ACTOR_KIND_HUMAN
        identity = stripped
    elif claims.get("sub"):
        kind = ACTOR_KIND_MACHINE
        identity = str(claims["sub"])
    else:
        raise IdentityClaimsError("no identity claims in token")

    issuer = str(claims.get("iss") or issuer_fallback)
    is_local = issuer == LOCAL_ISSUER

    return LayerActor(
        kind=kind,
        identity=identity,
        identity_verified=True,
        identity_provider="local" if is_local else "oidc",
        identity_issuer=issuer,
        identity_subject=str(claims.get("sub") or ""),
    )
