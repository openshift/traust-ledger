from __future__ import annotations

from enum import StrEnum


class EventKind(StrEnum):
    COUNTERSIGN = "countersign"
    SEVERITY = "severity"
    REGRESSION = "regression"
    IMPACT = "impact"
    VULN_SCAN = "vuln_scan"


BIRTH_EVENT_KINDS = frozenset(
    {
        EventKind.REGRESSION,
        EventKind.IMPACT,
        EventKind.VULN_SCAN,
    }
)
