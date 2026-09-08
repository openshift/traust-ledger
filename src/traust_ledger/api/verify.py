"""Layer verification — Merkle integrity and signature checking.

Library-level function: takes a layer dict, returns structured result.
No backend, no config, no HTTP concerns.
"""

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
    """Run Merkle integrity + optional signature check on a layer dict.

    Returns:
        {"passed": bool, "findings": [...], "checked_at": str}
    """
    findings: list[dict] = []

    def _sev(issue: IntegrityFinding) -> str:
        s = issue.severity
        return s.value if hasattr(s, "value") else str(s)

    for issue in verify_merkle_integrity(layer):
        findings.append({"severity": _sev(issue), "message": issue.message})

    if check_signatures:
        for issue in verify_merkle_signature(layer):
            findings.append({"severity": _sev(issue), "message": issue.message})

    return {
        "passed": len(findings) == 0,
        "findings": findings,
        "checked_at": datetime.now(UTC).isoformat(),
    }


__all__ = ["verify_layer"]
