"""Finding identity — fingerprinting and canonical forms.

SDK-tier: pure computation, no auth required. Import freely.
Future home: traust-sdk/contracts/ (SDK migration candidate).
"""

from traust_ledger._internal.identity import (
    ALGO_VERSION,
    DegenerateIdentity,
    canon_path,
    canon_repo,
    fingerprint,
    primary_cwe,
)

__all__ = [
    "ALGO_VERSION",
    "DegenerateIdentity",
    "canon_path",
    "canon_repo",
    "fingerprint",
    "primary_cwe",
]
