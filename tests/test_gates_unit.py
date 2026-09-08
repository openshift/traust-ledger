"""Direct unit tests for service.gates (complement e2e coverage)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from traust_contracts.v1.models.layer import LayerActor

from traust_ledger._internal.events.builders import VALIDITY_FALSE_POSITIVE
from traust_ledger._internal.gates import (
    reject_machine_disposition,
    reject_machine_human_lane,
    require_human_identity,
    require_rationale_length,
    require_timestamp_bounds,
    require_two_person,
    require_valid_epoch,
    require_verified_for_false_positive,
)
from traust_ledger._internal.kinds import EventKind
from traust_ledger.constants import TIMESTAMP_FUTURE_LIMIT_HOURS
from traust_ledger.service.errors import (
    IdentityRequiredError,
    IdentityUnverifiedError,
    InvalidEpochError,
    MachineDispositionError,
    RationaleTooShortError,
    TimestampFutureError,
    TwoPersonViolatedError,
)


class TestMachineGates:
    def test_empty_disposition_skips_machine_gate(self) -> None:
        reject_machine_disposition({"kind": "machine", "identity": "bot"}, {})

    def test_human_actor_skips_machine_disposition_gate(self) -> None:
        reject_machine_disposition(
            {"kind": "human", "identity": "alice"},
            {"validity": "confirmed"},
        )

    def test_machine_disposition_rejected(self) -> None:
        with pytest.raises(MachineDispositionError):
            reject_machine_disposition(
                {"kind": "machine", "identity": "bot"},
                {"validity": "confirmed"},
            )

    def test_machine_human_lane_rejected_for_countersign(self) -> None:
        with pytest.raises(MachineDispositionError):
            reject_machine_human_lane(
                LayerActor(kind="machine", identity="bot"),
                EventKind.COUNTERSIGN,
            )

    def test_machine_allowed_on_severity_lane_is_still_rejected(self) -> None:
        with pytest.raises(MachineDispositionError):
            reject_machine_human_lane(
                LayerActor(kind="machine", identity="bot"),
                EventKind.SEVERITY,
            )


class TestHumanIdentity:
    def test_countersign_requires_identity(self) -> None:
        with pytest.raises(IdentityRequiredError):
            require_human_identity(LayerActor(kind="human"), EventKind.COUNTERSIGN)

    def test_severity_lane_still_requires_identity(self) -> None:
        with pytest.raises(IdentityRequiredError):
            require_human_identity(LayerActor(kind="human"), EventKind.SEVERITY)


class TestFalsePositiveVerification:
    @pytest.mark.parametrize(
        "actor",
        [
            LayerActor(kind="human", identity="a@example.com", employee_status="active"),
            LayerActor(kind="human", identity="a@example.com", ldap_verified=True),
        ],
    )
    def test_active_human_allowed(self, actor: LayerActor) -> None:
        require_verified_for_false_positive(actor, VALIDITY_FALSE_POSITIVE)

    def test_unverified_human_rejected(self) -> None:
        with pytest.raises(IdentityUnverifiedError):
            require_verified_for_false_positive(
                LayerActor(
                    kind="human",
                    identity="a@example.com",
                    employee_status="terminated",
                ),
                VALIDITY_FALSE_POSITIVE,
            )

    def test_machine_skips_fp_verification(self) -> None:
        require_verified_for_false_positive(LayerActor(kind="machine"), VALIDITY_FALSE_POSITIVE)


class TestRationaleAndTimestamp:
    def test_rationale_too_short(self) -> None:
        with pytest.raises(RationaleTooShortError):
            require_rationale_length("short")

    def test_future_timestamp_rejected(self) -> None:
        future = (datetime.now(UTC) + timedelta(hours=TIMESTAMP_FUTURE_LIMIT_HOURS + 1)).isoformat()
        with pytest.raises(TimestampFutureError):
            require_timestamp_bounds(future)

    def test_naive_timestamp_treated_as_utc(self) -> None:
        require_timestamp_bounds("2020-06-15T12:00:00")


class TestValidEpoch:
    def test_empty_events_is_noop(self) -> None:
        require_valid_epoch({"events": []})

    def test_missing_metadata_rejected(self) -> None:
        with pytest.raises(InvalidEpochError):
            require_valid_epoch({"events": [{"event_id": "e1"}]})

    def test_epoch_out_of_range_rejected(self) -> None:
        with pytest.raises(InvalidEpochError):
            require_valid_epoch(
                {
                    "events": [{"event_id": "e1"}],
                    "metadata": {"merkle_epoch": 2},
                }
            )


class TestTwoPersonFingerprintMatch:
    """Two-person gate only fires for FP reassertion after exec-confirmed."""

    def _evt(self, finding_ref: str, **overrides: object) -> dict:
        base: dict = {
            "event_id": f"evt-{finding_ref}",
            "finding_ref": finding_ref,
            "recorded_at": "2025-01-01T00:00:00+00:00",
            "rationale": "test",
            "source": {"type": "interactive", "ref": "test", "actor": {"kind": "machine"}},
            "disposition": {},
        }
        base.update(overrides)
        return base

    def _exec_confirmed(self, finding_ref: str) -> dict:
        return self._evt(
            finding_ref,
            source={"type": "validation_report", "ref": "test", "actor": {"kind": "machine"}},
            disposition={"validity": "confirmed"},
        )

    def test_fingerprint_match_triggers_two_person(self) -> None:
        layer = {
            "events": [
                self._exec_confirmed("FP-001"),
                self._evt(
                    "OTHER-REF",
                    fingerprint="FP-001",
                    source={
                        "type": "interactive",
                        "ref": "test",
                        "actor": {
                            "kind": "human",
                            "identity": "alice@example.com",
                            "identity_verified": True,
                        },
                    },
                    disposition={"validity": "false_positive"},
                ),
            ]
        }
        with pytest.raises(TwoPersonViolatedError):
            require_two_person(layer, "FP-001", "alice@example.com", "false_positive")

    def test_unparseable_events_reject_gate(self) -> None:
        """Malformed events are present-and-unknown, not absent.

        A bare string in the events list is unparseable — the gate must
        refuse rather than silently dropping it (which allowed a single
        human to bypass execution-confirmed findings).
        """
        with pytest.raises(TwoPersonViolatedError):
            require_two_person(
                {"events": ["bad", {"finding_ref": "X"}]}, "X", "alice", "false_positive"
            )

    def test_empty_layer_passes(self) -> None:
        require_two_person({}, "X", "alice", "false_positive")

    def test_dual_ref_and_fingerprint_match(self) -> None:
        layer = {
            "events": [
                self._exec_confirmed("FP-1"),
                self._evt(
                    "FIND-1",
                    fingerprint="FP-1",
                    source={
                        "type": "interactive",
                        "ref": "test",
                        "actor": {
                            "kind": "human",
                            "identity": "bob@example.com",
                            "identity_verified": True,
                        },
                    },
                    disposition={"validity": "false_positive"},
                ),
            ]
        }
        with pytest.raises(TwoPersonViolatedError):
            require_two_person(layer, "FP-1", "bob@example.com", "false_positive")
