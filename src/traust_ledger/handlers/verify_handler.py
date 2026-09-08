"""Merkle integrity verification core."""

from __future__ import annotations

from datetime import UTC, datetime

from traust_ledger._internal.integrity import (
    IntegrityFinding,
    verify_merkle_integrity,
    verify_merkle_signature,
)


def verify_layer(
    layer: dict,
    *,
    check_signatures: bool = False,
) -> dict:
    """Run merkle integrity + optional signature check on a single layer.

    Returns structured result with pass/fail and findings list.
    """
    findings: list[dict] = []

    def _sev(issue: IntegrityFinding) -> str:
        s = issue.severity
        return s.value if hasattr(s, "value") else str(s)

    integrity_issues: list[IntegrityFinding] = verify_merkle_integrity(layer)
    for issue in integrity_issues:
        findings.append({"severity": _sev(issue), "message": issue.message})

    if check_signatures:
        sig_issues = verify_merkle_signature(layer)
        for issue in sig_issues:
            findings.append({"severity": _sev(issue), "message": issue.message})

    return {
        "passed": len(findings) == 0,
        "findings": findings,
        "checked_at": datetime.now(UTC).isoformat(),
    }
