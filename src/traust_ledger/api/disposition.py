"""Disposition merge engine — derives current state from event history.

SDK-tier: pure computation, no auth required. Import freely.
Future home: traust-sdk/contracts/ (SDK migration candidate).
"""

from traust_ledger._internal.disposition import (
    derive_disposition,
    event_class,
    is_actor_verified,
)

__all__ = [
    "derive_disposition",
    "event_class",
    "is_actor_verified",
]
