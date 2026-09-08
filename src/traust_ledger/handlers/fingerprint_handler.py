"""Fingerprint handler — pure computation, no persistence."""

from __future__ import annotations

from traust_ledger._internal.identity import DegenerateIdentity, fingerprint
from traust_ledger.models import FingerprintRequest, FingerprintResponse
from traust_ledger.service.errors import ValidationError


def compute_fingerprints(body: FingerprintRequest) -> FingerprintResponse:
    """Stamp fingerprints on eligible findings and return them.

    Mutates finding dicts in-place — the response returns the stamped list.
    """
    stamped = 0
    for finding in body.findings:
        if not isinstance(finding, dict):
            continue
        if not finding.get("locations") or not finding.get("cwes"):
            continue
        # strict at the producer — see the note in cli/commands/fingerprint.py and
        # plan item A5. New findings may not carry a degenerate identity; the 234
        # already in the corpus are grandfathered.
        try:
            finding["fingerprint"] = fingerprint(finding, body.repository, strict=True)
        except DegenerateIdentity as exc:
            raise ValidationError(
                f"{finding.get('id') or '<no id>'}: every location canonicalises to "
                f"empty, so this finding cannot be told apart from another in the "
                f"same repo with the same CWE. Give it the artifact it is about, or "
                f"a `repo:<subject>` marker for a genuinely repo-scoped finding."
            ) from exc
        stamped += 1
    return FingerprintResponse(findings=body.findings, stamped_count=stamped)
