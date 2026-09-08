#!/usr/bin/env python3
"""Cross-scan identity ON the ledger event (plan P1).

Before this, the fingerprint existed in report JSON and in the downstream
platform's Postgres, but NOT in the ledger — measured 0 of 122,982 events.
Events bound dispositions to `finding_ref`, which is scan-scoped and changes on
every re-audit, and the break was repaired at replay through
`metadata.finding_aliases`: a mutable table, outside the Merkle tree, with no
verifier anywhere in the codebase. Carrying identity on the event makes it
self-contained and — under leaf_format 2, where the leaf is the canonical JSON
of the whole event — tamper-evident for free.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from traust_ledger._internal.events import (
    FINGERPRINT_ALGO_CURRENT,
    attach_identity,
    compute_claim_hash,
    fingerprint_index,
)
from traust_ledger._internal.integrity import (
    stamp_merkle_metadata,
    verify_merkle_integrity,
)

FP_A = "a" * 64
FP_B = "b" * 64


def _report():
    return {
        "findings": [
            {"id": "R-1", "fingerprint": FP_A},
            {"id": "R-2", "fingerprint": FP_B},
            {"id": "R-3"},
        ]
    }


def _event(ref):
    return {
        "event_id": "e" + ref,
        "finding_ref": ref,
        "recorded_at": "2026-01-01T00:00:00Z",
        "source": {},
        "disposition": {},
        "rationale": "r",
    }


class TestFingerprintIndex(unittest.TestCase):
    def test_reads_stamped_values_only(self):
        """Never recomputes: the harness is the sole producer of identity, so a
        consumer that recomputes is a second implementation waiting to diverge."""
        self.assertEqual(fingerprint_index(_report()), {"R-1": FP_A, "R-2": FP_B})

    def test_unstamped_finding_is_absent_not_guessed(self):
        self.assertNotIn("R-3", fingerprint_index(_report()))


class TestAttachIdentity(unittest.TestCase):
    def test_stamps_fingerprint_and_algo(self):
        e = _event("R-1")
        self.assertTrue(attach_identity(e, fingerprint_index(_report())))
        self.assertEqual(e["fingerprint"], FP_A)
        self.assertEqual(e["fingerprint_algo"], FINGERPRINT_ALGO_CURRENT)

    def test_never_overwrites_an_existing_value(self):
        """An event is a historical observation. If identity later changes, that
        is a NEW event — "at time T this finding's identity was X" stays true."""
        e = _event("R-1")
        e["fingerprint"] = FP_B
        self.assertFalse(attach_identity(e, fingerprint_index(_report())))
        self.assertEqual(e["fingerprint"], FP_B)

    def test_absent_fingerprint_is_left_alone(self):
        e = _event("R-3")
        self.assertFalse(attach_identity(e, fingerprint_index(_report())))
        self.assertNotIn("fingerprint", e)

    def test_does_not_touch_event_id(self):
        """event_id is the validator-enforced idempotency key; re-keying it
        would orphan every existing event."""
        e = _event("R-1")
        before = e["event_id"]
        attach_identity(e, fingerprint_index(_report()))
        self.assertEqual(e["event_id"], before)


class TestIdentityIsMerkleCovered(unittest.TestCase):
    """The point of P1: identity inside the tree, not reachable only through a
    mutable metadata table."""

    def _layer(self):
        layer = {"metadata": {}, "events": [_event("R-1"), _event("R-2")]}
        idx = fingerprint_index(_report())
        for e in layer["events"]:
            attach_identity(e, idx)
        stamp_merkle_metadata(layer)
        return layer

    def test_layer_verifies_as_written(self):
        self.assertEqual(verify_merkle_integrity(self._layer()), [])

    def test_editing_a_fingerprint_breaks_the_root(self):
        layer = self._layer()
        layer["events"][0]["fingerprint"] = "0" * 64
        findings = verify_merkle_integrity(layer)
        self.assertTrue(findings, "a tampered fingerprint MUST break the root")
        self.assertTrue(any("merkle_root mismatch" in f.message for f in findings))

    def test_editing_the_algo_breaks_the_root(self):
        layer = self._layer()
        layer["events"][0]["fingerprint_algo"] = "v99"
        self.assertTrue(
            verify_merkle_integrity(layer),
            "the algo marker must be covered too, or a recipe change could be backdated silently",
        )


class TestComputeClaimHash(unittest.TestCase):
    def test_deterministic_for_claim_fields_only(self):
        finding = {
            "id": "F-1",
            "title": "SSRF",
            "severity": "high",
            "noise": "ignored by recipe",
        }
        first = compute_claim_hash(finding)
        second = compute_claim_hash({**finding, "noise": "different"})
        self.assertEqual(first, second)
        self.assertEqual(len(first), 64)

    def test_changes_when_claim_field_changes(self):
        base = {"id": "F-1", "title": "SSRF", "severity": "high"}
        altered = {**base, "title": "XSS"}
        self.assertNotEqual(compute_claim_hash(base), compute_claim_hash(altered))


if __name__ == "__main__":
    unittest.main()
