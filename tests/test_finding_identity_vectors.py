#!/usr/bin/env python3
"""Conformance-vector replay for traust_ledger._internal.identity.

tests/fixtures/finding-identity-vectors.json is the cross-implementation
contract for finding identity: external ports (Source Code Intelligence's
internal/pipeline/fingerprint.go is the known consumer) pin their
implementation against the same file, so tier-1 auto-confirm semantics
cannot drift silently between traust-ledger and any platform that
re-executes them. If a test here fails, either the change to
traust_ledger/identity.py was unintentional (fix the code) or identity
semantics changed deliberately — in that case regenerate the vectors,
bump the package MINOR version, and notify every port named above.
"""

import json
from pathlib import Path

from traust_ledger._internal.identity import canon_path, canon_repo, fingerprint

VECTORS = json.loads(
    (Path(__file__).resolve().parent / "fixtures" / "finding-identity-vectors.json").read_text()
)


def test_canon_repo_vectors():
    for case in VECTORS["canon_repo"]:
        assert canon_repo(case["input"]) == case["expected"], case


def test_canon_path_vectors():
    for case in VECTORS["canon_path"]:
        assert canon_path(case["input"]) == case["expected"], case


def test_fingerprint_vectors():
    for case in VECTORS["fingerprint"]:
        got = fingerprint(case["finding"], case["repo_url"])
        assert got == case["expected"], (case["name"], case["payload"], got)


def test_vectors_cover_the_identity_edge_cases():
    # The file is only a contract if the hard cases stay in it.
    names = " ".join(c["name"] for c in VECTORS["fingerprint"])
    for marker in ("dedupe", "CWE-0", "no locations", "subgroup", "broken metadata"):
        assert marker in names, f"vector coverage lost: {marker}"
