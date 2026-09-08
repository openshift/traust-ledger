"""Integrity verification — Merkle tree and signature checking.

SDK-tier: read-only trust verification (like sha256sum --check).
No secrets, no state mutation beyond the passed dict, no auth needed.

Merkle stamping (``stamp_merkle_metadata``) is internal to traust-ledger —
it runs inside ``finalize_layer`` which ``LedgerClient.sign()`` calls
atomically.  Callers never stamp manually; they call ``sign()``.

Signing operations go through ``LedgerClient.sign()`` or CLI.
"""

from traust_ledger._internal.integrity import (
    IntegrityFinding,
    Severity,
    verify_merkle_integrity,
    verify_merkle_signature,
)

__all__ = [
    "IntegrityFinding",
    "Severity",
    "verify_merkle_integrity",
    "verify_merkle_signature",
]
