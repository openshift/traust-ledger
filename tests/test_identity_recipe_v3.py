"""Regression fixtures for the canonical fingerprint recipe (algo_version v3).

v3 (2026-09-02) changed `primary_cwe` from "first listed" to "lowest by NUMBER",
so identity no longer depends on the order of a model-authored CWE list. Renamed
from test_identity_recipe_v2.py: the file pins whichever version is current, and
a name that lags the recipe is a trap for the next reader.

D7 retires the golden-vector suite because its purpose was holding a
second-language port to the recipe, and after D7 there is no port. This replaces
its regression role for the one implementation that remains: the recipe must not
change by accident, and each case below is a divergence that was measured, not
imagined.

All three were found on 2026-08-17/18 between traust_ledger and the Go SDK. All 12
golden vectors passed green through every one of them, because every vector is
ASCII with a well-formed CWE and no empty path.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from traust_ledger._internal.events import FINGERPRINT_ALGO_CURRENT
from traust_ledger._internal.identity import (
    ALGO_VERSION,
    ascii_lower,
    ascii_upper,
    canon_path,
    canon_repo,
    fingerprint,
    primary_cwe,
)

REPO = "https://github.com/org/repo"


def _f(paths, cwes=("CWE-79",)):
    return {"locations": [{"path": p} for p in paths], "cwes": list(cwes)}


# --- class 1: ASCII-only case folding --------------------------------------
# Python's str.lower() applies FULL Unicode case mapping, Go's strings.ToLower()
# SIMPLE, so 'İ' (U+0130) became 2 codepoints in one language and 1 in the other.
# Reachable: metadata.repository is an unconstrained string.


def test_case_folding_is_ascii_only():
    assert ascii_lower("ABZ") == "abz"
    assert ascii_upper("abz") == "ABZ"
    # Non-ASCII passes through untouched, in both directions. Written as
    # escapes: these are the codepoints whose case mappings differ between
    # runtimes, and several are visually indistinguishable from ASCII.
    for ch in (
        "\u0130",  # LATIN CAPITAL LETTER I WITH DOT ABOVE — full mapping gives 2 codepoints
        "\u0131",  # LATIN SMALL LETTER DOTLESS I
        "\u00df",  # LATIN SMALL LETTER SHARP S — upper() gives "SS"
        "\u1e9e",  # LATIN CAPITAL LETTER SHARP S
        "\u212a",  # KELVIN SIGN — lower() gives ASCII "k"
        "\u017f",  # LATIN SMALL LETTER LONG S — upper() gives "S"
    ):
        assert ascii_lower(ch) == ch, repr(ch)
        assert ascii_upper(ch) == ch, repr(ch)


def test_canon_repo_does_not_case_fold_non_ascii():
    assert (
        canon_repo("https://github.com/ORG/\u0130stanbul") == "https://github.com/org/\u0130stanbul"
    )


# --- class 2: blank CWE is CWE-0 -------------------------------------------
# The vector suite's own rules always said "'CWE-0' when absent/empty"; Go
# implemented it and Python returned "" for a whitespace-only value.


def test_blank_cwe_is_cwe_0():
    assert primary_cwe({"cwes": []}) == "CWE-0"
    assert primary_cwe({"cwes": [""]}) == "CWE-0"
    assert primary_cwe({"cwes": ["   "]}) == "CWE-0"
    assert primary_cwe({}) == "CWE-0"


def test_cwe_is_ascii_uppercased_and_stripped():
    assert primary_cwe({"cwes": [" cwe-79 "]}) == "CWE-79"


# --- class 3: empty canonical paths are dropped (v2, D8; unchanged in v3) -------------------
# `.`, `/`, `./`, `/./` all canonicalize to "". v1 tested the RAW value for
# truthiness, so "." survived and contributed an empty component (";src/a.go").
# 3,127 corpus locations are affected; 364 findings changed value.


def test_repo_root_markers_canonicalize_to_empty():
    for raw in (".", "/", "./", "/./"):
        assert canon_path(raw) == "", raw


def test_empty_canonical_paths_are_dropped_from_the_set():
    mixed = fingerprint(_f([".", "src/a.go"]), REPO)
    plain = fingerprint(_f(["src/a.go"]), REPO)
    assert mixed == plain

    # Every repo-root spelling drops out, not just "."
    for raw in ("/", "./", "/./"):
        assert fingerprint(_f([raw, "src/a.go"]), REPO) == plain, raw


def test_all_empty_path_set_matches_no_locations():
    """Unchanged from v1 — this is why 2,762 of the 3,127 did not move."""
    assert fingerprint(_f(["."]), REPO) == fingerprint(_f([]), REPO)


# --- the version itself ----------------------------------------------------


def test_algo_version_is_v3_and_the_event_stamp_tracks_it():
    assert ALGO_VERSION == "v3"
    assert FINGERPRINT_ALGO_CURRENT == ALGO_VERSION


# --- the domain restriction: strict mode (plan item 4) ----------------------
#
# Changing the recipe's MAPPING (adding a title or check id to the hash) would
# move stamped values and need an algo bump. Narrowing its DOMAIN does not: every
# accepted input hashes exactly as before. What it buys is that a degenerate
# finding cannot acquire an identity at all, at the one point nothing bypasses.


def test_strict_refuses_a_finding_with_no_usable_location():
    from traust_ledger._internal.identity import DegenerateIdentity

    for marker in (".", "/", "./", "/./"):
        try:
            fingerprint(_f([marker]), REPO, strict=True)
        except DegenerateIdentity as e:
            assert "no usable location" in str(e)
            assert "repo-scope-path.json" in str(e), "error must name the escape hatch"
        else:
            raise AssertionError(f"strict mode accepted {marker!r}")


def test_strict_refuses_a_finding_with_no_locations_at_all():
    from traust_ledger._internal.identity import DegenerateIdentity

    try:
        fingerprint(_f([]), REPO, strict=True)
    except DegenerateIdentity:
        pass
    else:
        raise AssertionError("strict mode accepted a finding with no locations")


def test_strict_accepts_a_pseudo_path():
    """The escape hatch works: repo-level facts get a real, stable key."""
    assert fingerprint(_f(["repo:maintenance"]), REPO, strict=True)
    # And they are distinct from each other, which is the whole point.
    assert fingerprint(_f(["repo:maintenance"]), REPO, strict=True) != fingerprint(
        _f(["repo:scorecard-onboarding"]), REPO, strict=True
    )


def test_strict_does_not_change_any_accepted_hash():
    """Domain restriction, not a mapping change — so no stamped value moves."""
    for paths in (["src/a.go"], ["src/a.go", "b.go"], [".", "src/a.go"], ["repo:maintenance"]):
        assert fingerprint(_f(paths), REPO) == fingerprint(_f(paths), REPO, strict=True), paths


def test_default_is_lenient_until_the_corpus_is_migrated():
    """~2,762 corpus findings would refuse to stamp if this flipped early.

    Backfill, then flip — the order P0.4 and P6 followed. When the migration
    lands, this test is the one that should be inverted.
    """
    assert fingerprint(_f(["."]), REPO)
