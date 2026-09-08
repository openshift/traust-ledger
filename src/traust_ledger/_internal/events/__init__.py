from traust_ledger._internal.identity import ALGO_VERSION

from ._core import (
    CLAIM_FIELDS,
    aliases_from_events,
    attach_identity,
    compute_claim_hash,
    compute_event_id,
    findings_from_events,
    fingerprint_index,
    make_alias_event,
)
from .builders import build_human_event, build_severity_event

FINGERPRINT_ALGO_CURRENT = ALGO_VERSION

__all__ = [
    "ALGO_VERSION",
    "CLAIM_FIELDS",
    "FINGERPRINT_ALGO_CURRENT",
    "aliases_from_events",
    "attach_identity",
    "build_human_event",
    "build_severity_event",
    "compute_claim_hash",
    "compute_event_id",
    "findings_from_events",
    "fingerprint_index",
    "make_alias_event",
]
