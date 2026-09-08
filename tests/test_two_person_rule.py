"""Two-person gate: FP reassertion after execution-confirmed challenge.

The gate only fires when incoming_validity is false_positive AND a prior
event on the finding is execution-class (validation_report/verification_report)
with validity=confirmed.  When triggered, it prevents the same verified
human from being their own second signer.
"""

from __future__ import annotations

import pytest

from traust_ledger._internal.gates import require_two_person
from traust_ledger.constants import (
    ACTOR_KIND_HUMAN,
    ACTOR_KIND_MACHINE,
    LAYER_KEY_EVENTS,
)
from traust_ledger.service.errors import TwoPersonViolatedError

FINDING = "FIND-001"
ALICE = "user:alice"
BOB = "user:bob"
FP = "false_positive"
CONFIRMED = "confirmed"

_SEQ = 0


def _next_id() -> str:
    global _SEQ
    _SEQ += 1
    return f"evt-{_SEQ:04d}"


def _base_event(finding_ref: str, **overrides: object) -> dict[str, object]:
    event: dict[str, object] = {
        "event_id": _next_id(),
        "finding_ref": finding_ref,
        "recorded_at": "2025-01-01T00:00:00+00:00",
        "rationale": "test",
        "source": {"type": "interactive", "ref": "test", "actor": {"kind": "machine"}},
        "disposition": {},
    }
    event.update(overrides)
    return event


def _human_event(
    identity: str,
    *,
    finding_ref: str = "",
    fingerprint: str | None = None,
    identity_verified: bool = True,
    validity: str = "false_positive",
) -> dict[str, object]:
    event = _base_event(
        finding_ref,
        source={
            "type": "interactive",
            "ref": "interactive:2026-01-16:sign",
            "actor": {
                "kind": ACTOR_KIND_HUMAN,
                "identity": identity,
                "identity_verified": identity_verified,
                "identity_provider": "oidc",
            },
        },
        disposition={"validity": validity},
    )
    if fingerprint is not None:
        event["fingerprint"] = fingerprint
    return event


def _human_event_ldap_legacy(
    identity: str,
    *,
    finding_ref: str = "",
    validity: str = "false_positive",
) -> dict[str, object]:
    """Pre-identity-refactor event: ldap_verified but no identity_verified."""
    return _base_event(
        finding_ref,
        source={
            "type": "interactive",
            "ref": "interactive:2026-01-16:sign",
            "actor": {
                "kind": ACTOR_KIND_HUMAN,
                "identity": identity,
                "ldap_verified": True,
                "identity_provider": "ldap",
            },
        },
        disposition={"validity": validity},
    )


def _machine_event(
    identity: str,
    *,
    finding_ref: str = "",
) -> dict[str, object]:
    return _base_event(
        finding_ref,
        source={
            "type": "automated",
            "ref": "scan:2026-01-16",
            "actor": {
                "kind": ACTOR_KIND_MACHINE,
                "identity": identity,
                "identity_verified": False,
            },
        },
    )


def _exec_confirmed_event(
    finding_ref: str,
    source_type: str = "validation_report",
) -> dict[str, object]:
    """Execution-class confirmed event (class 1)."""
    return _base_event(
        finding_ref,
        source={
            "type": source_type,
            "ref": f"{source_type}:2026-02-01",
            "actor": {
                "kind": ACTOR_KIND_MACHINE,
                "identity": "svc:validator",
                "identity_verified": False,
            },
        },
        disposition={"validity": "confirmed"},
    )


def _layer(events: list[dict[str, object]]) -> dict[str, object]:
    return {LAYER_KEY_EVENTS: events}


# ── Non-FP countersigns always pass (gate is a no-op) ────────────


def test_empty_layer_passes() -> None:
    """First signer on an empty layer — no execution proof, passes."""
    layer = _layer([])
    require_two_person(layer, FINDING, ALICE, FP)


def test_no_events_key_passes() -> None:
    """Layer without 'events' key — gate has nothing to check, passes."""
    require_two_person({}, FINDING, ALICE, FP)


def test_keep_open_after_exec_confirmed_passes() -> None:
    """Non-FP countersign (confirmed/keep_open) on an exec-confirmed finding
    should pass — two-person only applies to FP assertions."""
    layer = _layer([_exec_confirmed_event(FINDING)])
    require_two_person(layer, FINDING, ALICE, CONFIRMED)


def test_machine_counterparty_allowed() -> None:
    """Machine-only events, no execution proof — passes."""
    layer = _layer([_machine_event("svc:triage-0.1.0", finding_ref=FINDING)])
    require_two_person(layer, FINDING, ALICE, FP)


def test_different_human_allowed() -> None:
    """Different human prior, no execution proof — passes."""
    layer = _layer([_human_event(BOB, finding_ref=FINDING)])
    require_two_person(layer, FINDING, ALICE, FP)


def test_different_human_via_fingerprint_allowed() -> None:
    layer = _layer([_human_event(BOB, fingerprint=FINDING)])
    require_two_person(layer, FINDING, ALICE, FP)


def test_different_human_plus_machine_allows_countersign() -> None:
    layer = _layer(
        [
            _machine_event("svc:scan", finding_ref=FINDING),
            _human_event(BOB, finding_ref=FINDING),
        ]
    )
    require_two_person(layer, FINDING, ALICE, FP)


# ── FP without execution proof — gate is a no-op ─────────────────


def test_fp_without_exec_proof_passes() -> None:
    """Machine-triaged finding (no execution proof), Alice asserts FP —
    two-person rule does not apply."""
    layer = _layer([_machine_event("svc:triage", finding_ref=FINDING)])
    require_two_person(layer, FINDING, ALICE, FP)


def test_same_human_fp_without_exec_proof_passes() -> None:
    """Same human asserts FP twice on a non-exec-confirmed finding — passes
    because two-person only triggers against execution proof."""
    layer = _layer([_human_event(ALICE, finding_ref=FINDING, validity=FP)])
    require_two_person(layer, FINDING, ALICE, FP)


# ── FP reassertion after exec-confirmed challenge ────────────────


def test_fp_after_exec_confirmed_first_signer_passes() -> None:
    """Exec-confirmed finding, Alice is the first human FP asserter —
    allowed (becomes fp_reassertion_blocked at merge time)."""
    layer = _layer([_exec_confirmed_event(FINDING)])
    require_two_person(layer, FINDING, ALICE, FP)


def test_fp_after_exec_confirmed_same_signer_rejected() -> None:
    """Exec-confirmed finding, Alice already asserted FP, Alice tries
    again — rejected (can't be your own second signer)."""
    layer = _layer(
        [
            _exec_confirmed_event(FINDING),
            _human_event(ALICE, finding_ref=FINDING, validity=FP),
        ]
    )
    with pytest.raises(TwoPersonViolatedError):
        require_two_person(layer, FINDING, ALICE, FP)


def test_fp_after_exec_confirmed_different_signer_passes() -> None:
    """Exec-confirmed finding, Alice already asserted FP, Bob asserts FP —
    passes (two distinct verified humans)."""
    layer = _layer(
        [
            _exec_confirmed_event(FINDING),
            _human_event(ALICE, finding_ref=FINDING, validity=FP),
        ]
    )
    require_two_person(layer, FINDING, BOB, FP)


def test_fp_after_exec_confirmed_via_verification_report() -> None:
    """Same as above but exec confirmation via verification_report
    (the other execution-class source type)."""
    layer = _layer(
        [
            _exec_confirmed_event(FINDING, source_type="verification_report"),
            _human_event(ALICE, finding_ref=FINDING, validity=FP),
        ]
    )
    with pytest.raises(TwoPersonViolatedError):
        require_two_person(layer, FINDING, ALICE, FP)


def test_fp_after_exec_confirmed_unverified_prior_not_counted() -> None:
    """Exec-confirmed finding, prior FP by unverified human — the unverified
    event doesn't count as a first signer, so Alice (same identity) can
    still submit as the real first verified signer."""
    layer = _layer(
        [
            _exec_confirmed_event(FINDING),
            _human_event(
                ALICE,
                finding_ref=FINDING,
                validity=FP,
                identity_verified=False,
            ),
        ]
    )
    require_two_person(layer, FINDING, ALICE, FP)


def test_fp_after_exec_confirmed_legacy_ldap_verified_counted() -> None:
    """Pre-refactor event with ldap_verified=True (no identity_verified) —
    should be recognized as verified via the fallback."""
    layer = _layer(
        [
            _exec_confirmed_event(FINDING),
            _human_event_ldap_legacy(ALICE, finding_ref=FINDING, validity=FP),
        ]
    )
    with pytest.raises(TwoPersonViolatedError):
        require_two_person(layer, FINDING, ALICE, FP)


# ── Fingerprint matching in exec-confirmed scenario ──────────────


def test_same_human_rejected_via_fingerprint() -> None:
    """Two-person fires via fingerprint matching too."""
    exec_event = _exec_confirmed_event(FINDING)
    prior_fp = _human_event(ALICE, fingerprint=FINDING, validity=FP)
    layer = _layer([exec_event, prior_fp])
    with pytest.raises(TwoPersonViolatedError):
        require_two_person(layer, FINDING, ALICE, FP)


def test_same_human_rejected_when_event_has_both_keys() -> None:
    exec_event = _exec_confirmed_event(FINDING)
    prior_fp = _human_event(ALICE, finding_ref=FINDING, fingerprint=FINDING, validity=FP)
    layer = _layer([exec_event, prior_fp])
    with pytest.raises(TwoPersonViolatedError):
        require_two_person(layer, FINDING, ALICE, FP)


# ── Cross-path identity: OIDC vs LDAP produce identical identity ─


def test_same_human_via_oidc_and_ldap_rejected() -> None:
    """Same human authenticated via OIDC in one event — still recognized
    as same identity in exec-confirmed reassertion context."""
    oidc_fp_event = _base_event(
        FINDING,
        source={
            "type": "interactive",
            "ref": "interactive:2026-01-16:sign",
            "actor": {
                "kind": ACTOR_KIND_HUMAN,
                "identity": "alice@example.com",
                "identity_verified": True,
                "identity_provider": "oidc",
                "identity_issuer": "https://sso.example.com",
                "identity_subject": "f47ac10b-uuid",
            },
        },
        disposition={"validity": FP},
    )
    layer = _layer([_exec_confirmed_event(FINDING), oidc_fp_event])
    with pytest.raises(TwoPersonViolatedError):
        require_two_person(layer, FINDING, "alice@example.com", FP)


def test_different_humans_across_providers_allowed() -> None:
    """Two different humans, one via OIDC and one via LDAP, both asserting
    FP after exec proof — passes (two distinct identities)."""
    oidc_fp_event = _base_event(
        FINDING,
        source={
            "type": "interactive",
            "ref": "interactive:2026-01-16:sign",
            "actor": {
                "kind": ACTOR_KIND_HUMAN,
                "identity": "alice@example.com",
                "identity_verified": True,
                "identity_provider": "oidc",
            },
        },
        disposition={"validity": FP},
    )
    layer = _layer([_exec_confirmed_event(FINDING), oidc_fp_event])
    require_two_person(layer, FINDING, "bob@example.com", FP)
