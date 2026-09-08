"""Ledger core — disposition ledger kernel.

Three entry points (all OIDC-gated for reads AND writes):
    LedgerClient         — in-process Python SDK (traust_ledger.client)
    CLI                  — terminal: `ledger sign`, `ledger query`, etc.
    REST API             — HTTP service (traust_ledger.service)

Pure computation (no auth, no backend):
    traust_ledger.api.identity     — fingerprint, canon_path, primary_cwe
    traust_ledger.api.events       — compute_event_id, compute_claim_hash, aliases
    traust_ledger.api.disposition  — derive_disposition, is_actor_verified, event_class
    traust_ledger.api.integrity    — verify_merkle_integrity, verify_merkle_signature
    traust_ledger.api.reports      — report_sha256, check_report_digest
    traust_ledger.api.findings     — resolve_layer_findings
    traust_ledger.api.verify       — verify_layer

LedgerWriter is internal. All state mutations go through LedgerClient, CLI,
or REST API which enforce OIDC identity. Pure deterministic computation
(fingerprinting, event IDs, disposition derivation) is importable from api/.
"""
