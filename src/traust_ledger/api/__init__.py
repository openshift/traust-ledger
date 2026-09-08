"""traust_ledger.api — the public library surface.

Everything here is a stable, importable function that any Python consumer
can call directly. No HTTP, no CLI argparse, no backend config needed.

Modules:
    identity    — fingerprint, canon_path, canon_repo, primary_cwe
    events      — compute_event_id, compute_claim_hash, findings_from_events, ...
    disposition — derive_disposition, event_class, is_actor_verified
    integrity   — verify_merkle_*, Severity (stamping is internal to LedgerClient.sign())
    reports     — report_sha256, check_report_digest, check_artifact_digests
    findings    — resolve_layer_findings, FindingDisposition, FindingsSummary
    verify      — verify_layer (dict → pass/fail)

Usage:
    from traust_ledger.api import findings, verify
    findings.resolve_layer_findings(layer)

Note: stamp_and_sign lives in traust_ledger._internal.integrity (not public API).
"""
