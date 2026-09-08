#!/usr/bin/env python3
"""Generate the finding-identity golden-vector fixture.

The fixture is the cross-language conformance oracle for the finding
fingerprint. Any second implementation of the fingerprint — e.g. the
sci-api Go port — must reproduce every `expected_fingerprint` here
byte-for-byte. The `payload` field exposes the exact pre-hash string so an
implementer can debug a mismatch without reading Python.

Authoritative source: src/traust_ledger/_internal/identity.py (this repo). Writes into the
traust-contracts vectors tree (installed package or sibling checkout).
Regenerate with:

    python3 scripts/gen_identity_recipe_vectors.py

Commit the updated fixture in traust-contracts and run
traust-contracts/tests/test_compat.py (the out-of-band digest pin). If a vector's
hash legitimately changes, that is a fingerprint-recipe change and MUST come
with an algo_version bump.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from traust_ledger._internal.identity import (  # noqa: E402 — sys.path bootstrap
    canon_path,
    canon_repo,
    fingerprint,
    primary_cwe,
)

ALGO_VERSION = "v1"

# Each case is chosen to exercise a specific rule or a known SCI divergence
# (sci-api #46 / assessment V1). `why` documents which rule it pins.
CASES = [
    {
        "name": "single_path_with_cwe",
        "why": "baseline: one clean path, upper-case CWE present",
        "repo_url": "https://github.com/org/repo",
        "finding": {"locations": [{"path": "src/app.go"}], "cwes": ["CWE-79"]},
    },
    {
        "name": "multi_location_sorted_semicolon_join",
        "why": "SCI divergence: paths joined with ';' (not '|') and sorted as a set",
        "repo_url": "https://github.com/org/repo",
        "finding": {"locations": [{"path": "src/b.go"}, {"path": "src/a.go"}], "cwes": ["CWE-89"]},
    },
    {
        "name": "no_cwe_defaults_cwe0",
        "why": "SCI divergence: absent CWE must default to 'CWE-0', not ''",
        "repo_url": "https://github.com/org/repo",
        "finding": {"locations": [{"path": "config/values.yaml"}], "cwes": []},
    },
    {
        "name": "multiple_cwes_primary_first_upper_trim",
        "why": "primary CWE = first element, upper-cased and trimmed",
        "repo_url": "https://github.com/org/repo",
        "finding": {"locations": [{"path": "src/x.go"}], "cwes": ["cwe-798 ", "CWE-259"]},
    },
    {
        "name": "path_canonicalization",
        "why": "canon_path: backslash->slash, collapse //, strip leading ./ and /, trailing /",
        "repo_url": "https://github.com/org/repo",
        "finding": {
            "locations": [
                {"path": "./src/x.go"},
                {"path": "/etc/conf/"},
                {"path": "a\\b\\c.go"},
                {"path": "d//e.go"},
            ],
            "cwes": ["CWE-22"],
        },
    },
    {
        "name": "leading_dot_lstrip_quirk",
        "why": "canon_path uses lstrip('./') — strips a leading dot char too (quirk to reproduce)",
        "repo_url": "https://github.com/org/repo",
        "finding": {"locations": [{"path": "./.hidden/f.go"}], "cwes": ["CWE-200"]},
    },
    {
        "name": "duplicate_paths_deduped",
        "why": "locations are a set: repeated path collapses to one",
        "repo_url": "https://github.com/org/repo",
        "finding": {"locations": [{"path": "src/a.go"}, {"path": "src/a.go"}], "cwes": ["CWE-89"]},
    },
    {
        "name": "repo_git_suffix_stripped",
        "why": "canon_repo strips trailing .git; equals single_path_with_cwe",
        "repo_url": "https://github.com/org/repo.git",
        "finding": {"locations": [{"path": "src/app.go"}], "cwes": ["CWE-79"]},
    },
    {
        "name": "repo_scp_form_rewritten",
        "why": (
            "canon_repo rewrites git@host:path -> https://host/path; equals single_path_with_cwe"
        ),
        "repo_url": "git@github.com:org/repo.git",
        "finding": {"locations": [{"path": "src/app.go"}], "cwes": ["CWE-79"]},
    },
    {
        "name": "repo_uppercase_lowercased",
        "why": "canon_repo lowercases host and path; equals single_path_with_cwe",
        "repo_url": "https://GitHub.com/Org/Repo",
        "finding": {"locations": [{"path": "src/app.go"}], "cwes": ["CWE-79"]},
    },
    {
        "name": "repo_ssh_scheme_forced_https_keeps_userinfo",
        "why": (
            "canon_repo forces ssh:// -> https:// but leaves 'git@' userinfo "
            "(known quirk to reproduce byte-for-byte)"
        ),
        "repo_url": "ssh://git@github.com/org/repo.git",
        "finding": {"locations": [{"path": "src/app.go"}], "cwes": ["CWE-79"]},
    },
    {
        "name": "no_locations_empty_pathset",
        "why": "finding with no locations: middle payload field is empty",
        "repo_url": "https://github.com/org/repo",
        "finding": {"locations": [], "cwes": ["CWE-1004"]},
    },
]


def build():
    vectors = []
    for c in CASES:
        f, repo = c["finding"], c["repo_url"]
        paths = sorted(
            {canon_path(loc.get("path")) for loc in (f.get("locations") or []) if loc.get("path")}
        )
        payload = "|".join([canon_repo(repo), ";".join(paths), primary_cwe(f)])
        expected = fingerprint(f, repo)
        # invariant: expected == sha256(payload)
        assert expected == hashlib.sha256(payload.encode("utf-8")).hexdigest()
        vectors.append(
            {
                "name": c["name"],
                "why": c["why"],
                "input": {"repo_url": repo, "finding": f},
                "normalized": {
                    "canon_repo": canon_repo(repo),
                    "canon_paths_sorted_set": paths,
                    "primary_cwe": primary_cwe(f),
                },
                "payload": payload,
                "expected_fingerprint": expected,
            }
        )
    return {
        "algo_version": ALGO_VERSION,
        "hash": "sha256",
        "recipe": (
            "sha256( canon_repo(url) | ';'.join(sorted set of "
            "canon_path(locations[].path)) | primary_cwe )"
        ),
        "field_separator": "|",
        "path_separator": ";",
        "rules": {
            "canon_repo": (
                "strip/lower; git@host: -> https://host/ ; "
                "^(https?|ssh|git):// -> https:// ; strip trailing .git ; "
                "strip trailing /"
            ),
            "canon_path": (
                "strip; backslash->slash; collapse //; lstrip(chars './'); "
                "rstrip('/')  [line numbers live in `lines`, never here]"
            ),
            "primary_cwe": "first of finding.cwes upper()+strip(); 'CWE-0' when absent/empty",
            "locations": "deduped set of canon paths, sorted, ';'-joined",
        },
        "source": "traust_ledger.identity",
        "note": (
            "Cross-language conformance oracle for the finding fingerprint "
            "Any port must reproduce every "
            "expected_fingerprint byte-for-byte. A legitimate hash change is a "
            "recipe change and requires an algo_version bump."
        ),
        "vectors": vectors,
    }


def suite_digest(suite: dict) -> str:
    """Stable digest over (vector name -> expected hash). Any recipe change,
    vector removal, or rename moves it. Mirrored independently in
    traust-contracts/tests/test_compat.py."""
    lines = sorted(f"{v['name']}={v['expected_fingerprint']}" for v in suite["vectors"])
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def main():
    from traust_contracts.paths import vectors_dir

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--output",
        type=Path,
        default=vectors_dir() / "finding-identity-golden-vectors.json",
        help="fixture path (default: installed contracts vectors dir)",
    )
    ap.add_argument(
        "--allow-recipe-change",
        action="store_true",
        help="permit rewriting vectors for an UNCHANGED "
        "ALGO_VERSION (recipe change: requires a consumer "
        "re-fingerprint migration — see the module docstring)",
    )
    args = ap.parse_args()

    out = args.output
    suite = build()
    new_digest = suite_digest(suite)

    # Guard: refuse to silently redefine identity under the same algo_version.
    if out.exists():
        old = json.loads(out.read_text())
        old_digest = suite_digest(old)
        if (
            old.get("algo_version") == suite["algo_version"]
            and old_digest != new_digest
            and not args.allow_recipe_change
        ):
            sys.exit(
                f"REFUSING to rewrite {out.name}: hashes changed but "
                f"algo_version is still {suite['algo_version']!r}.\n"
                f"  old suite digest: {old_digest}\n"
                f"  new suite digest: {new_digest}\n"
                "A hash change IS a recipe change and invalidates every stored "
                "fingerprint in every consumer (e.g. the SCI platform).\n"
                "Either revert the recipe change, or: bump ALGO_VERSION, "
                "re-run, update EXPECTED_VECTOR_SUITE_DIGEST in "
                "traust-contracts/tests/test_compat.py, and ship a consumer "
                "re-fingerprint migration.\n"
                "If you are deliberately adding/renaming vectors under the "
                "same recipe, re-run with --allow-recipe-change and update "
                "the test pin in the same commit."
            )

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(suite, indent=2, sort_keys=False) + "\n")
    print(f"wrote {len(CASES)} vectors -> {out}")
    print(f"algo_version={suite['algo_version']} suite_digest={new_digest}")
    print(
        "If this digest changed, update EXPECTED_VECTOR_SUITE_DIGEST in "
        "traust-contracts/tests/test_compat.py (same commit)."
    )


if __name__ == "__main__":
    main()
