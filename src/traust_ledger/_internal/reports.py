"""The layer's link to its baseline report, content-addressed.

A layer has always named its report by **relative path** (`metadata.audit_report`),
which is only meaningful while the two sit in the same directory. Ledger plan §4.4.0
moves reports to object storage and keeps the ledger in git, so the link has to
survive the report leaving: `audit_report_sha256` says *which bytes*, and
`audit_report_ref` says *where* (opaque — resolved by an accessor, never by
string-munging a path).

This complements `metadata.claim_hashes` rather than duplicating it:

    claim_hashes        did any finding's CLAIM change?      (semantic, per finding)
    audit_report_sha256 are these the exact BYTES I read?    (whole file)

A claim-hash match with a digest mismatch is a legitimate, common state — a re-audit
that rewrites the file without changing any claim, or a corpus migration such as the
v1->v2 fingerprint re-stamp, which rewrote 361 reports without touching a claim.
That is precisely why the digest is **surfaced, never auto-healed**: silently
re-recording it would erase the only signal that the annotated bytes moved.

Not tamper-evidence yet: neither field is inside `merkle_signature_payload`, so the
backfill needs no re-stamp and no re-signature — and an attacker who can write the
layer can also rewrite the digest. Binding it into the signed payload is a format-3
change (plan §4.4.0a) requiring every layer to be re-signed.

EXTRACTION CANDIDATES (mixed concerns in this module):
- report_sha256, stamp_report_reference, check_report_digest
    → belongs in a "digest" or "content-addressing" module (pure hashing + metadata)
- _drop_signature_now_stale
    → belongs in integrity/signing (signature lifecycle)
- sibling_artifacts
    → belongs in a "corpus layout" or "backends/file" module (filesystem assumptions)
- stamp_artifact_digests, check_artifact_digests
    → combines filesystem traversal (sibling_artifacts) with metadata mutation;
      the traversal is a corpus concern, the stamping is an integrity concern
"""

from __future__ import annotations

import hashlib
from pathlib import Path

__all__ = [
    "check_artifact_digests",
    "check_report_digest",
    "report_sha256",
    "stamp_artifact_digests",
    "stamp_report_reference",
]

# Never digested: the layer is the thing doing the signing, and the corpus indexes are
# rebuilt in place rather than copied.
_NOT_AN_ARTIFACT = ("-findings-layer.json",)


def report_sha256(report: Path | bytes) -> str:
    """sha256 of a report's exact bytes — never of a re-serialization.

    Takes the file (or its bytes) rather than a parsed dict on purpose. The corpus
    is mixed on `ensure_ascii`, so `json.dumps` of a parsed report reproduces the
    original bytes for some producers and not others; hashing the parsed form would
    make the digest depend on who wrote the file.
    """
    data = report if isinstance(report, bytes) else Path(report).read_bytes()
    return hashlib.sha256(data).hexdigest()


def stamp_report_reference(layer: dict, report: Path | bytes, *, ref: str | None = None) -> bool:
    """Record the digest (and optionally the object ref) on a layer. True if changed.

    Idempotent: recording the same digest twice is a no-op, so writers can call this
    unconditionally.
    """
    meta = layer.setdefault("metadata", {})
    digest = report_sha256(report)
    changed = meta.get("audit_report_sha256") != digest
    meta["audit_report_sha256"] = digest
    if ref is not None and meta.get("audit_report_ref") != ref:
        meta["audit_report_ref"] = ref
        changed = True
    if changed:
        _drop_signature_now_stale(meta)
    return changed


def _drop_signature_now_stale(meta: dict) -> None:
    """D4b: a write that cannot re-sign drops the signature.

    Under signature format >= 3 the signed payload includes `audit_report_sha256`,
    so changing the digest invalidates the signature WITHOUT moving the Merkle root.
    `stamp_merkle_metadata` drops a stale signature only when the root changes, so
    nothing caught this: measured 2026-08-20, backfilling a digest onto
    feast__release-rhoai-2.25 left a signature that still claimed format 3 and failed
    verification, while `resign_layers_format3` skipped it as "already format 3"
    because it compares the format NUMBER, not whether the signature still verifies.

    Dropping is the safe half of D4b — a caller with a key re-signs immediately after,
    and a caller without one leaves an honestly unsigned layer rather than a signature
    that lies. Format 1 and 2 payloads do not cover the digest, so they are untouched.
    """
    if int(meta.get("merkle_signature_format") or 0) < 3:
        return
    if not meta.get("merkle_root_signature"):
        return
    meta.pop("merkle_root_signature", None)
    meta.pop("merkle_signing_method", None)
    meta.pop("merkle_signature_format", None)


def check_report_digest(layer: dict, report: Path | bytes) -> str | None:
    """None when the layer's recorded digest matches (or is absent); else a message.

    Absent is not a failure: 8,508 layers predate the field, and a layer written by
    an older harness is not evidence of tampering.
    """
    recorded = (layer.get("metadata") or {}).get("audit_report_sha256")
    if not recorded:
        return None
    actual = report_sha256(report)
    if actual == recorded:
        return None
    return (
        f"metadata.audit_report_sha256 {recorded[:12]}… does not match the report's "
        f"bytes {actual[:12]}… — the baseline was rewritten since this layer recorded "
        f"it. Legitimate after a re-audit or a corpus migration; re-record it "
        f"deliberately (baseline_claims.py record) rather than letting a writer "
        f"heal it silently."
    )


def sibling_artifacts(layer_path: Path) -> list[Path]:
    """The artifacts this layer vouches for: files beside it sharing its base.

    Measured 2026-08-21 over the corpus: 51,290 of 51,298 artifacts in layer-bearing
    directories match a layer's base prefix, so ownership by base is unambiguous and a
    directory holding two bases splits cleanly between their two layers.
    """
    name = layer_path.name
    if not name.endswith("-findings-layer.json"):
        return []
    base = name[: -len("-findings-layer.json")]
    return sorted(
        p
        for p in layer_path.parent.iterdir()
        if p.is_file() and p.name.startswith(f"{base}-") and not p.name.endswith(_NOT_AN_ARTIFACT)
    )


def stamp_artifact_digests(layer: dict, layer_path: Path) -> bool:
    """Record `metadata.artifact_digests` for this layer's siblings. True if changed.

    Plan R1. `audit_report_sha256` binds the ONE report a layer annotates; everything
    else beside it had no digest anywhere, so 85% of what a migration copies to object
    storage could not be verified afterwards — tolerable while git holds the original,
    and not a basis for deleting it.

    Digests are recomputed, not merged: unlike `claim_hashes`, which pins a claim so a
    later edit is visible, this records what the bytes ARE. A stale entry would assert
    something false about a file that legitimately changed. Under format 4 the map is
    inside the signature, so a change here correctly invalidates the signature.
    """
    meta = layer.setdefault("metadata", {})
    fresh = {p.name: report_sha256(p) for p in sibling_artifacts(layer_path)}
    if meta.get("artifact_digests") == fresh:
        return False
    if fresh:
        meta["artifact_digests"] = fresh
    else:
        meta.pop("artifact_digests", None)
    return True


def check_artifact_digests(layer: dict, layer_path: Path) -> list[str]:
    """Messages for every sibling whose bytes disagree with the recorded digest.

    Absent is not a failure — a layer written before format 4 records none. A file
    present on disk but missing from a populated map IS reported: after the migration
    that is how an unrecorded artifact would slip through unverifiable.
    """
    recorded = (layer.get("metadata") or {}).get("artifact_digests")
    if not recorded:
        return []
    out = []
    seen = set()
    for p in sibling_artifacts(layer_path):
        seen.add(p.name)
        want = recorded.get(p.name)
        if want is None:
            out.append(f"{p.name}: present on disk, absent from artifact_digests")
        elif (got := report_sha256(p)) != want:
            out.append(f"{p.name}: recorded {want[:12]}…, bytes hash {got[:12]}…")
    for name in sorted(set(recorded) - seen):
        out.append(f"{name}: recorded in artifact_digests, missing on disk")
    return out
