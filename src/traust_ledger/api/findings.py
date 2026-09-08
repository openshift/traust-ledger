"""Findings resolution — derive current state per finding from a layer dict.

Library-level function: takes a layer dict, returns typed results.
No backend, no config, no HTTP concerns. This is what the CLI, REST,
and direct Python consumers all call.

NOTE: This module is domain-coupled — it bakes "findings" semantics
(finding_ref, orphan detection, claim_hashes) directly into the ledger.
A generic ledger shouldn't know about findings. Candidate for removal
when traust-ledger splits into generic event ledger below / finding
semantics above (see sdk-restructure.md).
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime

from pydantic import BaseModel
from traust_contracts.v1.models.finding import Disposition
from traust_contracts.v1.models.report import ResolutionCounts, ValidityCounts

from traust_ledger._internal.disposition import derive_disposition
from traust_ledger._internal.events import aliases_from_events

# ─── Domain models ────────────────────────────────────────────────────────────
# These are return types of resolve_layer_findings — shared across api, CLI,
# REST, and external consumers like traust-engine.


class FindingDisposition(BaseModel):
    finding_ref: str
    disposition: Disposition
    event_count: int
    fingerprint: str | None = None
    orphan: bool | None = None


class FindingsSummary(BaseModel):
    by_validity: ValidityCounts
    by_resolution: ResolutionCounts


def resolve_layer_findings(layer: dict) -> tuple[list[FindingDisposition], FindingsSummary]:
    """Resolve current disposition per finding for a layer dict.

    Pure computation — deterministic given the layer contents.
    No backend, no config, no auth.
    """
    events = layer.get("events", [])
    now = datetime.now(UTC).isoformat()

    aliases = dict((layer.get("metadata") or {}).get("finding_aliases") or {})
    aliases.update(aliases_from_events(events))

    def _resolve_ref(ref: str) -> str:
        alias = aliases.get(ref)
        if alias and alias.get("confirmed"):
            return alias.get("new_id", ref)
        return ref

    by_finding: dict[str, list[dict]] = {}
    for e in events:
        if not isinstance(e, dict):
            continue
        ref = _resolve_ref(e.get("finding_ref", ""))
        if not ref:
            continue
        by_finding.setdefault(ref, []).append(e)

    # Baseline membership: claim_hashes pins every finding the baseline held
    # at the time it was pinned, so its key set IS the baseline roster.
    # Absent claim_hashes means UNKNOWN, not "not an orphan" — a layer that
    # never pinned claims cannot answer the question.
    claim_hashes = (layer.get("metadata") or {}).get("claim_hashes")
    baseline_refs = set(claim_hashes) if isinstance(claim_hashes, dict) else None

    result_findings = []
    for finding_ref, finding_events in sorted(by_finding.items()):
        stub = {"id": finding_ref}
        raw = derive_disposition(stub, finding_events, now)
        result_findings.append(
            FindingDisposition(
                finding_ref=finding_ref,
                disposition=Disposition(**raw),
                event_count=len(finding_events),
                fingerprint=_latest_fingerprint(finding_events),
                orphan=(None if baseline_refs is None else finding_ref not in baseline_refs),
            )
        )

    validity_counts = Counter(f.disposition.validity for f in result_findings)
    resolution_counts = Counter(f.disposition.resolution for f in result_findings)
    summary = FindingsSummary(
        by_validity=validity_counts,
        by_resolution=resolution_counts,
    )
    return result_findings, summary


def _latest_fingerprint(events: list[dict]) -> str | None:
    """The most recently recorded identity for this finding, or None.

    Newest-wins: identity is a historical observation and events are never
    re-stamped, so a finding whose file moved carries the old value on old
    events and the new one on new events. Events are in append order.

    Nullable by design: pre-6d events carry no stamp, and 27.6% of
    projection rows have no fingerprint available at all.
    """
    for e in reversed(events):
        if isinstance(e, dict) and e.get("fingerprint"):
            return str(e["fingerprint"])
    return None


__all__ = [
    "FindingDisposition",
    "FindingsSummary",
    "resolve_layer_findings",
]
