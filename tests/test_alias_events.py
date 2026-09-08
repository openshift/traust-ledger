#!/usr/bin/env python3
"""Rebaseline aliases as EVENTS, inside the Merkle tree (plan P2).

`finding_ref` is scan-scoped, so a re-audit renames every finding and the ledger
repaired the break at replay through `metadata.finding_aliases`. That table was
mutable, sat OUTSIDE the Merkle tree, and had no verifier anywhere in the
codebase (unlike `claim_hashes`, which self-checks against the report). Anyone
able to edit it could re-point a `false_positive` or `accepted_risk` verdict at a
different finding and the root would still verify. 1,418 layers carried one.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from traust_ledger._internal.events import (
    aliases_from_events,
    make_alias_event,
)
from traust_ledger._internal.integrity import (
    stamp_merkle_metadata,
    verify_merkle_integrity,
)

MACHINE = {"kind": "machine", "identity": "harness"}
HUMAN = {"kind": "human", "identity": "reviewer1"}


def _alias(old, new, matched_by, when, actor=MACHINE, **kw):
    return make_alias_event(
        old,
        new,
        matched_by,
        recorded_at=when,
        source_ref=f"rebaseline:{when}",
        actor=actor,
        rationale="rebaseline mapping recorded as an event",
        **kw,
    )


class TestAliasEventShape(unittest.TestCase):
    def test_marked_as_rebaseline_and_carries_no_disposition(self):
        e = _alias("OLD-1", "NEW-1", "fingerprint", "2026-01-01T00:00:00Z")
        self.assertEqual(e["source"]["type"], "rebaseline")
        self.assertEqual(
            e["disposition"], {}, "an alias is not a disposition — it must not imply one"
        )
        self.assertEqual(e["alias"]["new_finding_ref"], "NEW-1")


class TestProjection(unittest.TestCase):
    def test_shapes_like_the_legacy_table(self):
        p = aliases_from_events([_alias("OLD-1", "NEW-1", "fingerprint", "2026-01-01T00:00:00Z")])
        self.assertEqual(p["OLD-1"]["new_id"], "NEW-1")
        self.assertEqual(p["OLD-1"]["matched_by"], "fingerprint")
        self.assertEqual(p["OLD-1"]["mapped_at"], "2026-01-01T00:00:00Z")

    def test_confirmation_is_a_later_event_not_an_edit(self):
        """The append-only expression of 'a human confirmed this'."""
        proposal = _alias("OLD-1", "NEW-1", "path_cwe", "2026-01-01T00:00:00Z")
        confirm = _alias(
            "OLD-1", "NEW-1", "manual", "2026-02-01T00:00:00Z", actor=HUMAN, confirmed=True
        )
        p = aliases_from_events([proposal, confirm])
        self.assertTrue(p["OLD-1"]["confirmed"])
        self.assertEqual(p["OLD-1"]["confirmed_by"], "reviewer1")
        self.assertEqual(p["OLD-1"]["matched_by"], "manual")

    def test_rejection_supersedes_a_proposal(self):
        p = aliases_from_events(
            [
                _alias("OLD-1", "NEW-1", "title", "2026-01-01T00:00:00Z"),
                _alias(
                    "OLD-1", "NEW-1", "manual", "2026-02-01T00:00:00Z", actor=HUMAN, rejected=True
                ),
            ]
        )
        self.assertTrue(p["OLD-1"]["rejected"])

    def test_non_alias_events_are_ignored(self):
        plain = {"event_id": "x", "finding_ref": "F-1", "disposition": {}}
        self.assertEqual(aliases_from_events([plain]), {})


class TestAliasesAreMerkleCovered(unittest.TestCase):
    """The point of P2: the mapping is inside the tree, so re-pointing a
    disposition can no longer verify clean."""

    def _layer(self):
        layer = {
            "metadata": {},
            "events": [
                _alias("OLD-1", "NEW-1", "fingerprint", "2026-01-01T00:00:00Z", confirmed=True)
            ],
        }
        stamp_merkle_metadata(layer)
        return layer

    def test_verifies_as_written(self):
        self.assertEqual(verify_merkle_integrity(self._layer()), [])

    def test_repointing_the_successor_breaks_the_root(self):
        layer = self._layer()
        layer["events"][0]["alias"]["new_finding_ref"] = "ATTACKER-CHOSEN-1"
        findings = verify_merkle_integrity(layer)
        self.assertTrue(findings, "re-pointing an alias MUST break the root")
        self.assertTrue(any("merkle_root mismatch" in f.message for f in findings))

    def test_forging_confirmation_breaks_the_root(self):
        layer = self._layer()
        layer["events"][0]["alias"]["matched_by"] = "manual"
        self.assertTrue(
            verify_merkle_integrity(layer), "upgrading the match tier must not verify clean"
        )


if __name__ == "__main__":
    unittest.main()
