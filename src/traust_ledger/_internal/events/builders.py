from __future__ import annotations

from traust_contracts.v1.models.layer import (
    LayerActor,
    LayerDisposition,
    LayerEvent,
    LayerSource,
)

from ._core import compute_event_id

SOURCE_TYPE_INTERACTIVE = "interactive"
VALIDITY_FALSE_POSITIVE = "false_positive"
VALIDITY_CONFIRMED = "confirmed"
DECISION_FALSE_POSITIVE = "false_positive"
DECISION_OVERRIDE_FALSE_POSITIVE = "override_false_positive"
SEVERITY_REF_PREFIX = "severity"
DATE_PREFIX_LEN = 10

FP_DECISIONS = frozenset({DECISION_FALSE_POSITIVE, DECISION_OVERRIDE_FALSE_POSITIVE})


def _interactive_ref(recorded_at: str, suffix: str) -> str:
    date_prefix = recorded_at[:DATE_PREFIX_LEN]
    return f"{SOURCE_TYPE_INTERACTIVE}:{date_prefix}:{suffix}"


def _validity_for_decision(decision: str) -> str:
    if decision in FP_DECISIONS:
        return VALIDITY_FALSE_POSITIVE
    return VALIDITY_CONFIRMED


def build_human_event(
    finding_ref: str,
    decision: str,
    rationale: str,
    actor: LayerActor,
    recorded_at: str,
) -> LayerEvent:
    validity = _validity_for_decision(decision)
    if not actor.identity:
        raise ValueError("actor identity is required to build a human event")
    source_ref = _interactive_ref(recorded_at, actor.identity)
    return LayerEvent(
        event_id=compute_event_id(source_ref, finding_ref, validity, None),
        finding_ref=finding_ref,
        recorded_at=recorded_at,
        occurred_at=recorded_at,
        source=LayerSource(
            type=SOURCE_TYPE_INTERACTIVE,
            ref=source_ref,
            actor=actor,
        ),
        disposition=LayerDisposition(validity=validity),
        rationale=rationale,
    )


def build_severity_event(
    finding_ref: str,
    level: str,
    rationale: str,
    actor: LayerActor,
    recorded_at: str,
) -> LayerEvent:
    suffix = f"{SEVERITY_REF_PREFIX}:{level}"
    source_ref = _interactive_ref(recorded_at, suffix)
    return LayerEvent(
        event_id=compute_event_id(source_ref, finding_ref, None, None),
        finding_ref=finding_ref,
        recorded_at=recorded_at,
        occurred_at=recorded_at,
        source=LayerSource(
            type=SOURCE_TYPE_INTERACTIVE,
            ref=source_ref,
            actor=actor,
        ),
        disposition=LayerDisposition(severity=level),
        rationale=rationale,
    )


__all__ = [
    "FP_DECISIONS",
    "SOURCE_TYPE_INTERACTIVE",
    "VALIDITY_CONFIRMED",
    "VALIDITY_FALSE_POSITIVE",
    "build_human_event",
    "build_severity_event",
]
