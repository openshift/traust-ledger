"""CLI actor resolution — verify token and produce a LayerActor."""

from __future__ import annotations

import sys

from traust_contracts.v1.models.layer import LayerActor

from traust_ledger.auth import AuthResolutionError, TokenVerificationError, resolve_auth


def require_verified_actor() -> LayerActor | None:
    """Resolve + cryptographically verify the current token → LayerActor.

    Returns None (and prints an error) if auth fails.
    """
    try:
        cred = resolve_auth()
    except AuthResolutionError as exc:
        print(str(exc), file=sys.stderr)
        return None

    try:
        return cred.verify()
    except TokenVerificationError as exc:
        print(f"Token verification failed: {exc}", file=sys.stderr)
        return None
