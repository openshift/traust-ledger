"""Replay the ported recipe fixtures — the regression net D7 says not to lose.

These 12 cases came from `traust-contracts`
`vectors/v1/finding-identity-golden-vectors.json`, ported here on 2026-08-18
before that suite was retired. Under D7 only the harness computes identity, so
there is no second-language port left to hold to a shared oracle — but the recipe
still must not change by accident, and these cover ground
`test_identity_recipe_v2.py` does not: scheme rewriting, `.git` stripping, the scp
form, path dedup, the `lstrip` cutset quirk, CWE trimming.

They are fixtures, not a contract. If a change here is intentional, the recipe's
ALGO_VERSION moves and `v1_expected_fingerprint` in the fixture file is what makes
the move visible instead of a silent re-baseline.
"""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from traust_ledger._internal.identity import (
    ALGO_VERSION,
    DegenerateIdentity,
    canon_path,
    canon_repo,
    fingerprint,
    primary_cwe,
)

FIXTURES = Path(__file__).parent / "fixtures" / "identity-recipe-vectors.json"
SUITE = json.loads(FIXTURES.read_text(encoding="utf-8"))
VECTORS = SUITE["vectors"]


def test_fixture_file_is_pinned_to_this_recipe_version():
    assert SUITE["algo_version"] == ALGO_VERSION, (
        "fixtures were generated under a different recipe version — regenerate "
        "deliberately, and only alongside an ALGO_VERSION bump"
    )


def test_suite_is_not_silently_shrinking():
    """The retired suite had 12 cases. Losing one should be a failure, not a diff."""
    assert len(VECTORS) >= 12
    assert len({v["name"] for v in VECTORS}) == len(VECTORS), "duplicate vector names"


@pytest.mark.parametrize("vector", VECTORS, ids=[v["name"] for v in VECTORS])
def test_vector_fingerprint(vector):
    inp = vector["input"]
    assert fingerprint(inp["finding"], inp["repo_url"]) == vector["expected_fingerprint"]


@pytest.mark.parametrize("vector", VECTORS, ids=[v["name"] for v in VECTORS])
def test_vector_normalized_parts(vector):
    """Pin the intermediate forms too, so a failure localizes to one primitive."""
    norm = vector.get("normalized")
    if not norm:
        pytest.skip("vector records no normalized breakdown")
    inp = vector["input"]
    if "canon_repo" in norm:
        assert canon_repo(inp["repo_url"]) == norm["canon_repo"]
    if "primary_cwe" in norm:
        assert primary_cwe(inp["finding"]) == norm["primary_cwe"]
    if "canon_paths_sorted_set" in norm:
        paths = sorted(
            {
                c
                for loc in (inp["finding"].get("locations") or [])
                if (c := canon_path(loc.get("path")))
            }
        )
        assert paths == [p for p in norm["canon_paths_sorted_set"] if p]


def test_v3_moved_exactly_the_multi_cwe_vector():
    """Evidence, kept executable, and updated for v3.

    v2 changed only inputs nobody had specified: all 12 vectors hashed identically
    under v1 and v2, which is why the empty-path change needed no re-baseline — and
    why this suite could never have caught that divergence.

    **v3 is the first recipe change that moves a value here.** `primary_cwe` went
    from "first listed" to "lowest by NUMBER", so exactly one vector moves: the
    multi-CWE one, where `["cwe-798 ", "CWE-259"]` selected CWE-798 by position and
    now selects CWE-259 by number. Everything else must still match its v1 hash — a
    second moved vector would mean the change reached further than intended.
    """
    moved = [v for v in VECTORS if v.get("moved_in_v3")]
    assert [v["name"] for v in moved] == ["multiple_cwes_lowest_number_upper_trim"], (
        "v3 should move the multi-CWE vector and nothing else"
    )
    for v in VECTORS:
        if v.get("moved_in_v3"):
            continue
        assert v["unchanged_from_v1"]
        assert v["expected_fingerprint"] == v["v1_expected_fingerprint"]


def test_the_empty_pathset_vector_is_what_strict_mode_refuses():
    """Ties the fixture suite to the open migration.

    `no_locations_empty_pathset` is a legitimate v2 hash and exactly the shape
    that collapses identity to (repo, '', cwe). Lenient mode keeps hashing it
    until the ~2,762-finding migration lands; strict mode already refuses it.
    """
    vector = next(v for v in VECTORS if v["name"] == "no_locations_empty_pathset")
    inp = vector["input"]
    assert fingerprint(inp["finding"], inp["repo_url"]) == vector["expected_fingerprint"]
    with pytest.raises(DegenerateIdentity):
        fingerprint(inp["finding"], inp["repo_url"], strict=True)
