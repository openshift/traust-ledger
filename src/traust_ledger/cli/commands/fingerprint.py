from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from traust_ledger._internal.identity import DegenerateIdentity, fingerprint


def _stamp_findings(findings: list[dict], repo_url: str | None) -> int:
    count = 0
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        if not finding.get("locations") or not finding.get("cwes"):
            continue
        # **strict at the producer, grandfathered in the corpus (plan A5).**
        # A location that canonicalises to empty (`.`, `/`) collapses identity to
        # (repo, "", cwe), so unrelated findings in one repo become one finding and
        # a disposition on either silently covers both — measured at 432 findings,
        # 214 of them colliding, worst case 18 sharing an identity. Refusing here
        # stops NEW ones without touching the 234 that remain: those were stamped
        # under a lenient recipe and rewriting history is not this call's business.
        try:
            finding["fingerprint"] = fingerprint(finding, repo_url, strict=True)
        except DegenerateIdentity:
            raise ValueError(
                f"{finding.get('id') or '<no id>'}: every location canonicalises to "
                f"empty (paths: "
                f"{[loc.get('path') for loc in finding.get('locations') or []]}), so "
                f"this finding cannot be told apart from any other in the same repo "
                f"with the same CWE. Give it the artifact it is about — for an absent "
                f"file that is still the file's path, and for a genuinely repo-scoped "
                f"finding use a `repo:<subject>` marker such as repo:ci-pipeline."
            ) from None
        count += 1
    return count


def cmd_fingerprint(args: argparse.Namespace) -> int:
    """ledger fingerprint <report.json> — stamp finding fingerprints in-place."""
    path = Path(args.report_path)
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read report: {exc}", file=sys.stderr)
        return 1

    if not isinstance(report, dict):
        print("error: report must be a JSON object", file=sys.stderr)
        return 1

    metadata = report.get("metadata") or {}
    repo_url = metadata.get("repository") if isinstance(metadata, dict) else None

    stamped = 0
    findings = report.get("findings")
    if isinstance(findings, list):
        stamped += _stamp_findings(findings, repo_url)

    summary = report.get("findings_summary")
    if isinstance(summary, dict):
        summary_findings = summary.get("findings")
        if isinstance(summary_findings, list):
            stamped += _stamp_findings(summary_findings, repo_url)

    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"stamped {stamped} fingerprint(s)")
    return 0
