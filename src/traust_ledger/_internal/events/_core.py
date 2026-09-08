from __future__ import annotations

import json

from traust_ledger._internal.hashing import sha256_hex
from traust_ledger._internal.identity import ALGO_VERSION

# TODO: source from traust-contracts schema instead of hardcoding
CLAIM_FIELDS = ("id", "title", "severity", "cwes", "locations", "description", "remediation")


def compute_claim_hash(finding: dict) -> str:
    """Single call-site for claim tamper-evidence; harness merge engine imports
    this rather than reimplementing."""
    payload = json.dumps(
        {k: finding.get(k) for k in CLAIM_FIELDS},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return sha256_hex(payload)


def compute_event_id(
    source_ref: str,
    finding_ref: str,
    validity: str | None,
    resolution: str | None,
) -> str:
    """Deterministic idempotency key — single definition imported by harness
    merge engine and report validator."""
    payload = f"{source_ref}|{finding_ref}|{validity or ''}|{resolution or ''}"
    return sha256_hex(payload)


def fingerprint_index(report: dict) -> dict[str, str]:
    """Reads stamped fingerprints — harness is the sole producer (3D)."""
    return {
        f["id"]: f["fingerprint"]
        for f in (report.get("findings") or [])
        if f.get("id") and f.get("fingerprint")
    }


def attach_identity(event: dict, index: dict[str, str]) -> bool:
    """Stamp fingerprint onto event. Returns True if stamped, False if already
    present. Never overwrites — identity is a historical observation. Does not
    touch event_id (idempotency key)."""
    if event.get("fingerprint"):
        return False
    fp = index.get(event.get("finding_ref"))
    if not fp:
        return False
    event["fingerprint"] = fp
    event["fingerprint_algo"] = ALGO_VERSION
    return True


def make_alias_event(
    old_ref: str,
    new_ref: str,
    matched_by: str,
    *,
    recorded_at: str,
    source_ref: str,
    actor: dict,
    rationale: str,
    confirmed: bool | None = None,
    rejected: bool | None = None,
    similarity: float | None = None,
    path_overlap: float | None = None,
    from_report: str | None = None,
    note: str | None = None,
) -> dict:
    """Rebaseline alias event (P2): old finding_ref -> successor. Confirmation
    or rejection is a LATER event, never an edit to this one."""
    alias: dict = {"new_finding_ref": new_ref, "matched_by": matched_by}
    for k, v in (
        ("confirmed", confirmed),
        ("rejected", rejected),
        ("similarity", similarity),
        ("path_overlap", path_overlap),
        ("from_report", from_report),
        ("note", note),
    ):
        if v is not None:
            alias[k] = v
    return {
        "event_id": compute_event_id(source_ref, old_ref, None, None),
        "finding_ref": old_ref,
        "recorded_at": recorded_at,
        "source": {"type": "rebaseline", "ref": source_ref, "actor": actor},
        "disposition": {},
        "rationale": rationale,
        "alias": alias,
    }


def aliases_from_events(events) -> dict[str, dict]:
    """Project `{old_ref: alias-entry}` from alias events. Later events for the
    same finding_ref supersede earlier ones (append-only confirmation/rejection)."""
    out: dict[str, dict] = {}
    for e in events or []:
        a = e.get("alias")
        if not a or not e.get("finding_ref"):
            continue
        entry = {
            "new_id": a["new_finding_ref"],
            "matched_by": a["matched_by"],
            "mapped_at": e.get("recorded_at"),
        }
        for src, dst in (
            ("confirmed", "confirmed"),
            ("rejected", "rejected"),
            ("similarity", "similarity"),
            ("path_overlap", "path_overlap"),
            ("from_report", "from_report"),
            ("note", "note"),
        ):
            if src in a:
                entry[dst] = a[src]
        actor = (e.get("source") or {}).get("actor") or {}
        if entry.get("confirmed") and actor.get("identity"):
            entry["confirmed_by"] = actor["identity"]
            entry["confirmed_at"] = e.get("recorded_at")
        out[e["finding_ref"]] = entry
    return out


def findings_from_events(events) -> dict[str, dict]:
    """Project `{finding_id: finding}` from event-carried findings (B1).
    Caller must prefer baseline over event-carried copies."""
    out: dict[str, dict] = {}
    for e in events or []:
        f = e.get("finding")
        if not isinstance(f, dict):
            continue
        fid = f.get("id")
        if not fid:
            continue
        out[fid] = f
    return out
