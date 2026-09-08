"""Report metadata — digests, references, artifact stamping.

SDK-tier: pure computation / read-only checks, no auth required.
stamp_report_reference mutates the passed dict (no I/O, no auth).
"""

from traust_ledger._internal.reports import (
    check_artifact_digests,
    check_report_digest,
    report_sha256,
    stamp_artifact_digests,
    stamp_report_reference,
)

__all__ = [
    "check_artifact_digests",
    "check_report_digest",
    "report_sha256",
    "stamp_artifact_digests",
    "stamp_report_reference",
]
