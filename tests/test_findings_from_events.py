#!/usr/bin/env python3
"""findings_from_events — projecting event-carried finding claims (plan B1).

Sibling of aliases_from_events: both project state out of the append-only event
stream rather than reading a mutable table.
"""

from __future__ import annotations

from traust_ledger._internal.events import findings_from_events


def _ev(fid, title="t", **extra):
    f = {"id": fid, "title": title}
    f.update(extra)
    return {"finding_ref": fid, "finding": f}


class TestProjection:
    def test_empty_inputs(self):
        assert findings_from_events(None) == {}
        assert findings_from_events([]) == {}

    def test_projects_by_finding_id(self):
        out = findings_from_events([_ev("A-1"), _ev("B-2")])
        assert sorted(out) == ["A-1", "B-2"]

    def test_later_event_supersedes(self):
        """Append-only correction: a producer appends, never edits."""
        out = findings_from_events([_ev("A-1", "first"), _ev("A-1", "corrected")])
        assert out["A-1"]["title"] == "corrected"

    def test_events_without_a_finding_block_are_ignored(self):
        # The overwhelming majority of events are dispositions, not arrivals.
        plain = {"finding_ref": "A-1", "disposition": {"resolution": "open"}}
        assert findings_from_events([plain]) == {}

    def test_malformed_blocks_are_skipped_not_raised(self):
        # Replay must never crash on a bad layer — it reports, it does not die.
        bad = [
            {"finding": "not a dict"},
            {"finding": {}},
            {"finding": {"title": "no id"}},
            {"finding": None},
        ]
        assert findings_from_events(bad) == {}

    def test_carries_the_full_claim_through(self):
        out = findings_from_events(
            [
                _ev(
                    "A-1",
                    "SSRF",
                    severity="high",
                    cwes=["CWE-918"],
                    origin="vuln-scan",
                    validation_status="not_verified",
                )
            ]
        )
        f = out["A-1"]
        assert f["severity"] == "high"
        assert f["cwes"] == ["CWE-918"]
        assert f["origin"] == "vuln-scan"
        assert f["validation_status"] == "not_verified"


class TestSiblingSymmetry:
    def test_same_supersession_rule_as_aliases(self):
        """Both projections resolve duplicates by last-event-wins."""
        from traust_ledger._internal.events import aliases_from_events

        evs = [
            {
                "finding_ref": "A-1",
                "recorded_at": "2026-01-01T00:00:00Z",
                "alias": {"new_finding_ref": "X-1", "matched_by": "title"},
            },
            {
                "finding_ref": "A-1",
                "recorded_at": "2026-02-01T00:00:00Z",
                "alias": {"new_finding_ref": "X-2", "matched_by": "fingerprint"},
            },
        ]
        assert aliases_from_events(evs)["A-1"]["new_id"] == "X-2"
        assert findings_from_events([_ev("A-1", "old"), _ev("A-1", "new")])["A-1"]["title"] == "new"
