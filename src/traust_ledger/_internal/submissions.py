from __future__ import annotations

import json

from traust_ledger._internal.hashing import sha256_hex
from traust_ledger.models import EventEnvelope


def submission_id_for_event(envelope: EventEnvelope) -> str:
    payload = json.dumps(
        {"kind": envelope.kind, "event": envelope.event},
        sort_keys=True,
        separators=(",", ":"),
    )
    return sha256_hex(payload)
