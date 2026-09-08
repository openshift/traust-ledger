"""Tests for interactive human event builders."""

from __future__ import annotations

import pytest
from traust_contracts.v1.models.layer import LayerActor

from traust_ledger._internal.events import build_human_event, build_severity_event
from traust_ledger._internal.events.builders import (
    DECISION_FALSE_POSITIVE,
    DECISION_OVERRIDE_FALSE_POSITIVE,
    SOURCE_TYPE_INTERACTIVE,
    VALIDITY_CONFIRMED,
    VALIDITY_FALSE_POSITIVE,
)

FINDING_REF = "SEC-42"
RECORDED_AT = "2026-03-15T14:30:00Z"
RATIONALE = "Reviewed source and confirmed exploit path."
ACTOR_A = LayerActor(kind="human", identity="alice")
ACTOR_B = LayerActor(kind="human", identity="bob")
SEVERITY_LEVEL = "high"


@pytest.mark.parametrize(
    ("decision", "expected_validity"),
    [
        (DECISION_FALSE_POSITIVE, VALIDITY_FALSE_POSITIVE),
        (DECISION_OVERRIDE_FALSE_POSITIVE, VALIDITY_FALSE_POSITIVE),
        ("keep_open", VALIDITY_CONFIRMED),
    ],
    ids=["false_positive", "override_fp", "confirmed"],
)
def test_human_event_validity_mapping(decision: str, expected_validity: str) -> None:
    event = build_human_event(FINDING_REF, decision, RATIONALE, ACTOR_A, RECORDED_AT)
    assert event.disposition.validity == expected_validity
    assert event.finding_ref == FINDING_REF
    assert event.recorded_at == RECORDED_AT
    assert event.occurred_at == RECORDED_AT
    assert event.source.type == SOURCE_TYPE_INTERACTIVE
    assert event.rationale == RATIONALE


def test_human_event_determinism() -> None:
    first = build_human_event(FINDING_REF, "keep_open", RATIONALE, ACTOR_A, RECORDED_AT)
    second = build_human_event(FINDING_REF, "keep_open", RATIONALE, ACTOR_A, RECORDED_AT)
    assert first.event_id == second.event_id


def test_human_event_different_signer_different_id() -> None:
    alice = build_human_event(FINDING_REF, "keep_open", RATIONALE, ACTOR_A, RECORDED_AT)
    bob = build_human_event(FINDING_REF, "keep_open", RATIONALE, ACTOR_B, RECORDED_AT)
    assert alice.event_id != bob.event_id


def test_human_event_same_signer_same_day_dedupes() -> None:
    morning = build_human_event(
        FINDING_REF, "keep_open", RATIONALE, ACTOR_A, "2026-03-15T08:00:00Z"
    )
    evening = build_human_event(
        FINDING_REF, "keep_open", RATIONALE, ACTOR_A, "2026-03-15T20:00:00Z"
    )
    assert morning.event_id == evening.event_id


def test_severity_event_shape() -> None:
    event = build_severity_event(FINDING_REF, SEVERITY_LEVEL, RATIONALE, ACTOR_A, RECORDED_AT)
    assert event.event_id
    assert event.finding_ref == FINDING_REF
    assert event.recorded_at == RECORDED_AT
    assert event.disposition.severity == SEVERITY_LEVEL
    assert event.source.type == SOURCE_TYPE_INTERACTIVE
    assert "severity" in event.source.ref


def test_severity_event_determinism() -> None:
    first = build_severity_event(FINDING_REF, SEVERITY_LEVEL, RATIONALE, ACTOR_A, RECORDED_AT)
    second = build_severity_event(FINDING_REF, SEVERITY_LEVEL, RATIONALE, ACTOR_A, RECORDED_AT)
    assert first.event_id == second.event_id


def test_actor_fields_preserved_by_builder() -> None:
    actor = LayerActor(
        kind="human",
        identity="alice@example.com",
        identity_verified=True,
        identity_provider="oidc",
    )
    event = build_human_event(FINDING_REF, "keep_open", RATIONALE, actor, RECORDED_AT)
    assert event.source.actor.identity_verified is True
    assert event.source.actor.identity_provider == "oidc"


def test_actor_typed_model() -> None:
    actor = LayerActor(
        kind="human",
        identity="jdoe@example.com",
        identity_verified=True,
        display_name="Jane Doe",
    )
    event = build_human_event(FINDING_REF, "keep_open", RATIONALE, actor, RECORDED_AT)
    assert event.source.actor.identity == "jdoe@example.com"
    assert event.source.actor.display_name == "Jane Doe"
