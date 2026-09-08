# Data model

**Proposal — not implemented.** Normalized schema for `LAAS_BACKEND_TYPE=db`,
replacing the single JSON-blob `layers` table in `traust_ledger/backends/db.py`.

```mermaid
erDiagram
    layers ||--o{ events : contains

    layers {
        text layer_id PK
        jsonb metadata
        jsonb needs_review
        timestamptz updated_at
    }

    events {
        text layer_id FK
        int seq PK
        text event_id UK
        text finding_ref
        timestamptz recorded_at
        text validity
        text resolution
        text actor_kind
        text actor_identity
        jsonb event
    }
```

Additional indexes (not expressible in the diagram above): `events (layer_id, finding_ref)`,
`events (layer_id, recorded_at)`.

`events.layer_id → layers.layer_id`, `ON DELETE RESTRICT`.
