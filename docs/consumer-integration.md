# Consumer integration guide

traust-ledger exposes a **two-tier** public surface:

## SDK tier (pure computation — import freely)

Deterministic algorithms consumers need for pre-validation, matching, and
preparing data before submission. No auth required; safe for library use.

| Import path | Key exports |
|---|---|
| `traust_ledger.identity` | `fingerprint`, `canon_path`, `canon_repo`, `primary_cwe` |
| `traust_ledger.events` | `compute_event_id`, `compute_claim_hash`, `attach_identity`, `findings_from_events` |
| `traust_ledger.disposition` | `derive_disposition`, `is_actor_verified`, `event_class` |
| `traust_ledger.reports` | `report_sha256`, `check_report_digest`, `check_artifact_digests` |

These paths are stable across versions. `_internal/` may change freely.

**Note:** `identity`, `events`, and `disposition` are SDK migration candidates —
they may eventually move to `traust-sdk/contracts/`. Import paths will be shimmed.

## Gated tier (state changes — OIDC required)

All mutations require verified identity. Three entry points:

| Entry point | When to use |
|-------------|-------------|
| `LedgerClient` | In-process Python (import `traust_ledger.client`) |
| CLI | Shell scripts, pipelines (`ledger submit`, `ledger sign`, …) |
| REST API | Remote / cross-language consumers |

Never import `LedgerWriter` or `_internal/` modules for writes.

### LedgerClient (Python SDK)

```python
from traust_ledger.client import LedgerClient

client = LedgerClient.from_env()  # reads LAAS_TOKEN, LAAS_DATA_DIR, etc.
client.submit("layer-id", events)
client.sign("layer-id")
client.verify("layer-id")
result = client.query_findings("layer-id")
```

Requires `LAAS_TOKEN` (OIDC JWT) or `LEDGER_LOCAL_IDENTITY` (for local
auth — a token is auto-minted). No optional extras needed — `LedgerClient`
is importable from bare `traust-ledger`.

### REST API

For services that talk to traust-ledger over the network:

| Endpoint | Purpose |
|---|---|
| `POST /v1/ledger/layers/{id}/submit` | Batch event + queue submission |
| `POST /v1/ledger/review-items/resolve` | Resolve a queued review item |
| `GET /v1/ledger/layers/{id}/findings` | Per-layer resolved dispositions |
| `GET /v1/ledger/layers/{id}/events` | Raw event log |
| `GET /v1/ledger/layers/{id}/verify` | Merkle integrity check |
| `GET /v1/ledger/layers` | List known layers |
| `POST /v1/ledger/layers/{id}/fingerprint` | Server-side fingerprint stamping |

## CLI

For services that run traust-ledger in the same environment:

| Command | Purpose |
|---|---|
| `ledger submit <events.json>` | Submit events (same as REST batch) |
| `ledger countersign <finding_ref>` | Two-person countersign |
| `ledger fingerprint <report.json>` | Stamp fingerprints on a report |
| `ledger materialize --to <url>` | Populate a queryable projection table |
| `ledger query layers` | List layers |
| `ledger query findings <layer>` | Resolved findings for a layer |
| `ledger query events <layer>` | Event log for a layer |
| `ledger query verify <layer>` | Merkle integrity check |

### Materialization

`ledger materialize` reads the service backend and writes resolved findings into
a SQL store (SQLite or Postgres):

```bash
export LAAS_BACKEND_TYPE=file
export LAAS_DATA_DIR=/path/to/layers

# Populate a local SQLite
ledger materialize --to sqlite:///findings.db

# Populate Postgres (credentials via env, not argv)
export LAAS_MATERIALIZE_URL=postgresql://user:pass@host/db
ledger materialize

# Only specific layers
ledger materialize --to sqlite:///findings.db --layer repo-a --layer repo-b

# Print the schema DDL
ledger materialize --ddl
```

The projection table (`materialized_findings`) is keyed on `(layer_id, finding_ref)`.
Re-running is idempotent. Each layer commits independently.

### Layer ID derivation

If your layers live in nested directories (not the flat service backend), raw
filenames will collide. Use the CLI or REST layer-id in all downstream keying.
The service assigns layer IDs at ingest time; the materialize CLI handles its
own ID derivation internally.

## Boundary

```
traust-ledger provides (via LedgerClient/CLI/REST):
  ✓ event submission (append-only, idempotent, signed)
  ✓ disposition resolution (per-layer findings)
  ✓ integrity verification (merkle tree, signatures)
  ✓ fingerprint stamping (deterministic identity recipe)
  ✓ materialized projection (queryable SQL table)
  ✓ queue management (needs_review lifecycle)

traust-ledger does NOT provide:
  ✗ tree iteration / filesystem traversal
  ✗ cross-layer joins or aggregation
  ✗ dashboard queries or scoring
  ✗ deployment topology awareness
  ✗ additional schema beyond materialized_findings
```
