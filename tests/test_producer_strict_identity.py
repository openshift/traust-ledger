"""New findings may not carry a degenerate identity; existing ones are grandfathered.

A location that canonicalises to empty (`.`, `/`, `./`) produces an empty path set,
so the fingerprint collapses to `(repo, "", cwe)` and unrelated findings in one
repository become one identity — a disposition on either silently covers both.
Measured on the corpus 2026-09-02: 432 such findings, 214 of them colliding, worst
case 18 sharing a single identity in `csi-external-provisioner`.

`fingerprint(strict=True)` has existed for this since 2026-08-18 but stayed off,
because flipping it while the corpus was full of degenerate findings would have
refused them at stamp time. This turns it on **at the two producer entry points
only** — `ledger fingerprint` and the REST fingerprint handler — both of which stamp
*new* findings. The 234 still in the corpus keep their lenient stamps: they were
recorded under the recipe of their day, and rewriting history is not this call's
business (plan A5, "grandfather and flip").

Note what is NOT constrained: `location.path` in `report.schema.json` is
`{type: string, minLength: 1}` with no enum, and the repo-scope pseudo-path list in
contracts is a registry whose own description says "prefer a real path; reach for
these only when there is none". So any non-empty path is accepted here — a real
file, a controlled `repo:provenance`, or a subject like `repo:ci-pipeline`. Only
paths that canonicalise away are refused.
"""

from __future__ import annotations

import pytest

from traust_ledger.cli.commands.fingerprint import _stamp_findings

REPO = "https://github.com/example/proj"


def _finding(path: str | None, fid: str = "FIND-001") -> dict:
    f: dict = {"id": fid, "cwes": ["CWE-79"]}
    if path is not None:
        f["locations"] = [{"path": path}]
    return f


@pytest.mark.parametrize("path", ["cmd/main.go", "SECURITY.md", "a/b/c.yaml"])
def test_real_paths_are_stamped(path):
    findings = [_finding(path)]
    assert _stamp_findings(findings, REPO) == 1
    assert findings[0]["fingerprint"]


@pytest.mark.parametrize(
    "path",
    [
        "repo:provenance",  # in the contracts registry
        "repo:branch-protection",  # in the contracts registry
        "repo:ci-pipeline",  # not in it — the path field is unconstrained
        "repo:networkpolicy",
    ],
)
def test_repo_scoped_subjects_are_stamped(path):
    """The registry is advisory, not a closed vocabulary — schema allows any string."""
    findings = [_finding(path)]
    assert _stamp_findings(findings, REPO) == 1


@pytest.mark.parametrize("path", [".", "/", "./", "/./"])
def test_repo_root_markers_are_refused(path):
    """The whole point: identity that cannot distinguish must not be minted."""
    with pytest.raises(ValueError, match="canonicalises to empty"):
        _stamp_findings([_finding(path)], REPO)


def test_the_refusal_says_what_to_do():
    """A refusal that does not name the remedy just moves the confusion."""
    with pytest.raises(ValueError) as exc:
        _stamp_findings([_finding(".", fid="FIND-042")], REPO)
    msg = str(exc.value)
    assert "FIND-042" in msg, "must name the finding"
    assert "['.']" in msg, "must show the offending paths"
    assert "repo:" in msg, "must offer the repo-scoped escape hatch"


def test_findings_without_locations_are_skipped_not_refused():
    """Unchanged behaviour — a finding with no locations at all was never stamped."""
    findings = [_finding(None)]
    assert _stamp_findings(findings, REPO) == 0
    assert "fingerprint" not in findings[0]


def test_a_mixed_location_set_survives_on_its_real_path():
    """`.` alongside a real file is not degenerate — the empty component is dropped."""
    f = {"id": "FIND-1", "cwes": ["CWE-79"], "locations": [{"path": "."}, {"path": "cmd/main.go"}]}
    assert _stamp_findings([f], REPO) == 1


def test_grandfathering_is_by_construction():
    """Nothing here reads or rewrites an existing stamp.

    The flip lives at the producer, which mints identities for new findings. The 234
    degenerate findings already in the corpus are untouched because no code path in
    this module looks at them — stated as a test so a future 'tidy-up' that adds a
    corpus sweep here has to justify itself.
    """
    import inspect

    from traust_ledger.cli.commands import fingerprint as mod

    src = inspect.getsource(mod)
    assert "rglob" not in src and "walk" not in src, (
        "the producer must not sweep the corpus; grandfathering depends on it"
    )
