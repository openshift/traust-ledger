"""Event computation — IDs, hashes, aliases, identity attachment.

SDK-tier: pure computation, no auth required. Import freely.
Future home: traust-sdk/contracts/ (SDK migration candidate).
"""

from traust_ledger._internal.events import (
    CLAIM_FIELDS,
    FINGERPRINT_ALGO_CURRENT,
    aliases_from_events,
    attach_identity,
    compute_claim_hash,
    compute_event_id,
    findings_from_events,
    fingerprint_index,
    make_alias_event,
)

__all__ = [
    "CLAIM_FIELDS",
    "FINGERPRINT_ALGO_CURRENT",
    "aliases_from_events",
    "attach_identity",
    "compute_claim_hash",
    "compute_event_id",
    "findings_from_events",
    "fingerprint_index",
    "make_alias_event",
]
