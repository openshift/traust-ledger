"""`primary_cwe` picks the lowest CWE by NUMBER (v3), not the first listed.

v2 took `cwes[0]`, so a finding's identity depended on the order a model happened
to write a model-authored list: 27,496 of 75,128 corpus findings carry more than
one CWE, and 11,085 would hash differently under a positional rule. Two audits of
the same finding could therefore fail to correlate purely on list order.

The trap this file exists to pin: **`min()` over these strings is lexicographic**,
so `min(["CWE-937", "CWE-1104"])` is `CWE-1104` — `'1'` precedes `'9'`. That reading
disagrees with the numeric one on **8,893 corpus findings**. Both are deterministic
and either would serve identity; numeric was chosen (Michele, 2026-09-02) because
"lowest CWE" means 937 before 1104, and the Go SDK reimplements this from the
docstring. A recipe that contradicts its own wording earns a v4 the day someone
notices.
"""

from __future__ import annotations

import pytest

from traust_ledger._internal.identity import ALGO_VERSION
from traust_ledger.api.identity import fingerprint, primary_cwe

REPO = "https://github.com/example/proj"


def test_algo_version_is_v3():
    """The recipe moved, so stamps must record a new version."""
    assert ALGO_VERSION == "v3"


@pytest.mark.parametrize(
    "cwes, expected",
    [
        (["CWE-937", "CWE-1104"], "CWE-937"),
        (["CWE-1104", "CWE-937"], "CWE-937"),
        (["CWE-79"], "CWE-79"),
        (["CWE-89", "CWE-79", "CWE-352"], "CWE-79"),
    ],
)
def test_picks_the_lowest_number(cwes, expected):
    assert primary_cwe({"cwes": cwes}) == expected


def test_not_lexicographic():
    """The specific disagreement, stated as a test so it cannot regress quietly."""
    cwes = ["CWE-937", "CWE-1104"]
    assert min(cwes) == "CWE-1104", "precondition: min() is lexicographic"
    assert primary_cwe({"cwes": cwes}) == "CWE-937"


def test_order_independent():
    """The whole point: identity must not depend on how the list was written."""
    a = {"cwes": ["CWE-89", "CWE-79"], "locations": [{"path": "cmd/main.go"}]}
    b = {"cwes": ["CWE-79", "CWE-89"], "locations": [{"path": "cmd/main.go"}]}
    assert primary_cwe(a) == primary_cwe(b) == "CWE-79"
    assert fingerprint(a, REPO) == fingerprint(b, REPO)


@pytest.mark.parametrize(
    "cwes, expected",
    [
        ([], "CWE-0"),
        (["  "], "CWE-0"),
        (None, "CWE-0"),
    ],
)
def test_absent_or_blank_is_cwe_zero(cwes, expected):
    """Unchanged from v2 — the vector suite and the Go SDK both require it."""
    assert primary_cwe({"cwes": cwes}) == expected


def test_unnumbered_entry_sorts_last_rather_than_raising():
    """Identity must not fail on input the schema permits."""
    assert primary_cwe({"cwes": ["CWE-xx", "CWE-79"]}) == "CWE-79"
    # and if every entry is unnumbered, it still returns something total
    assert primary_cwe({"cwes": ["CWE-xx"]}) == "CWE-XX"


def test_case_and_whitespace_normalised():
    assert primary_cwe({"cwes": ["  cwe-79  "]}) == "CWE-79"


def test_v3_moves_the_stamp_for_a_reordered_multi_cwe_finding():
    """Why this is a version bump: an existing v2 stamp does not match v3.

    v2 hashed `cwes[0]`; for a finding whose first CWE is not its lowest, v3 hashes
    a different CWE and therefore produces a different fingerprint. That is the
    11,085 the plan's A4 counts, and the reason stamps carry ALGO_VERSION.
    """
    f = {"cwes": ["CWE-937", "CWE-1104"], "locations": [{"path": "cmd/main.go"}]}
    v3 = fingerprint(f, REPO)
    # what v2 would have produced: the first-listed CWE
    v2_equivalent = fingerprint(
        {"cwes": ["CWE-1104"], "locations": [{"path": "cmd/main.go"}]}, REPO
    )
    assert v3 != v2_equivalent
    # and v3 equals hashing the lowest-numbered CWE alone
    assert v3 == fingerprint({"cwes": ["CWE-937"], "locations": [{"path": "cmd/main.go"}]}, REPO)
