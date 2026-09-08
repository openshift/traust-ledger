"""Test-only identity verifiers for multi-actor scenarios (e.g. two-person rule)."""

from __future__ import annotations

from fastapi import Request
from traust_contracts.v1.models.layer import LayerActor

from traust_ledger.constants import ACTOR_KIND_HUMAN
from traust_ledger.service.identity.tokens import extract_bearer_token


class TokenActorVerifier:
    """Maps bearer token values to distinct LayerActors (two-person rule tests)."""

    def verify(self, request: Request) -> LayerActor:
        token = extract_bearer_token(request)
        if token.startswith("alice"):
            return LayerActor(
                kind=ACTOR_KIND_HUMAN,
                identity="user:alice",
                identity_verified=True,
                identity_provider="oidc",
            )
        if token.startswith("bob"):
            return LayerActor(
                kind=ACTOR_KIND_HUMAN,
                identity="user:bob",
                identity_verified=True,
                identity_provider="oidc",
            )
        return LayerActor(
            kind=ACTOR_KIND_HUMAN,
            identity=f"user:{token[:8]}",
            identity_verified=True,
            identity_provider="oidc",
        )
