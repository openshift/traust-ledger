"""FastAPI auth dependencies — thin wiring layer.

All identity logic lives in ``traust_ledger.service.identity``.
This module provides the FastAPI ``Depends`` callables that delegate
to the ``ActorResolver`` on ``app.state``.
"""

from __future__ import annotations

from fastapi import Request
from traust_contracts.v1.models.layer import LayerActor


async def resolve_actor(request: Request) -> LayerActor:
    """Resolve request identity via the app's ActorResolver."""
    resolver = request.app.state.resolver
    return resolver.resolve(request)


async def require_identity(request: Request) -> None:
    """Gate: verify identity is valid but don't inject the actor."""
    resolver = request.app.state.resolver
    resolver.resolve(request)
