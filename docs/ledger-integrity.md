# Ledger integrity

What guarantees a layer is tamper-evident and who-acted is preserved.

## The invariant

The identity port (service layer) proves **who called the API**. This document
covers what happens **after** identity is proven: how the actor lands in the
ledger's integrity structure so it can be verified independently of the service
that wrote it.

## Write paths and their integrity guarantees

All three entry points (LedgerClient, CLI, REST API) converge on the same
handlers (`traust_ledger.handlers.*`), which call `LedgerWriter` and
`sign_handler.sign_layer()`. The integrity guarantees are identical regardless
of entry point.

### Events (`POST /v1/ledger/events` / `LedgerClient.submit()` / `ledger submit`)

```
identity gate → resolve actor → domain gates → stamp actor on event source
→ append event → recompute Merkle → sign root (if configured) → persist
```

The actor from the identity port is:
1. Copied defensively (`model_copy`)
2. Checked against domain gates (human required, verified for FP, two-person)
3. Stamped into `event.source.actor` — this is the Merkle leaf content
4. The `event_id` is derived from the actor + timestamp + finding ref

If signing is required and fails, the write is rejected. No unsigned event can
land when `LAAS_SIGNING_REQUIRED=true`.

### Reports (`POST /v1/ledger/reports`)

```
identity gate → converter produces events with machine actor → append events
→ recompute Merkle → sign root → persist
```

Reports are machine-lane. The converter stamps its own `LayerActor(kind="machine")`
from report content — the authenticated caller's identity gates access but does
not override what the converter stamps. This is deliberate: the provenance of a
machine report is the scanner that produced it, not the transport identity.

## Fail-closed enforcement

| Check | Where | Failure mode |
|---|---|---|
| Identity required | `require_identity` / `resolve_actor` in route deps | 401 before handler |
| Signing required | `require_signing_configured` at handler entry | Startup error if key missing |
| Signing on write | `finalize_layer` after Merkle recompute | 422 if sign fails with `signing_required=true` |
| Human identity | `require_human_identity` | 422 if human event lacks identity |
| Verified for FP | `require_verified_for_false_positive` | 422 if unverified |
| Two-person rule | `require_two_person` | 422 if same signer |
| Machine exclusion | `reject_machine_human_lane` | 422 if machine on human lane |

All write gates are fail-closed: missing configuration or invalid state
**rejects** the write, never degrades silently.

## What the Merkle leaf contains

Each event in the layer carries:

```json
{
  "source": {
    "type": "interactive" | "automated",
    "ref": "...",
    "actor": {
      "kind": "human" | "machine",
      "identity": "alice@example.com",
      "identity_verified": true,
      "identity_provider": "oidc",
      "identity_issuer": "https://sso.example.com/realms/prod",
      "identity_subject": "alice@example.com",
      "employee_status": "active"
    }
  }
}
```

The Merkle tree covers this content. Tampering with the actor, the event
payload, or the order of events invalidates the root. The signature over the
root makes this externally verifiable.

## `event_id` derivation

`event_id` includes the actor identity:
`{source_type}:{date}:{actor.identity}` for interactive events. This ties the
event's identity to its content hash — changing who-acted changes the ID.

## Merkle-root signing

| Variable | Default | What it does |
|---|---|---|
| `LAAS_SIGNING_REQUIRED` | `false` | Unsigned writes fail when true |
| `LAAS_SIGNING_METHOD` | `keypair` | `keypair` (cosign) or `sigstore-oidc` (keyless) |
| `LAAS_SIGNING_KEY_PATH` | *(unset)* | Cosign private key path |
| `LAAS_SIGNING_CA_URL` / `LAAS_SIGNING_TLOG_URL` | *(unset)* | Private Fulcio/Rekor endpoints |

Both `LAAS_SIGNING_*` and `HARNESS_SIGNING_*` prefixes are honoured (legacy).

> **The default is unsigned.** Set both `LAAS_SIGNING_KEY_PATH` and
> `LAAS_SIGNING_REQUIRED=true` for any real deployment. Setting only the key
> path means a broken mount degrades silently; setting only `REQUIRED` fails
> loudly.

## What's not pluggable

The domain schema (`layer.schema.json`), `event_id`/fingerprint computation,
the Merkle algorithm, and the append-only write contract. These are what let a
layer written by one deployment verify under another — regardless of which
identity provider was used.

## In-process SDK path

`LedgerClient` (`traust_ledger.client`) is the in-process Python SDK. It
requires an OIDC token at construction (`LAAS_TOKEN`) and stamps actor identity
on every operation. All integrity guarantees (Merkle, signing) apply.

`LedgerWriter` is internal — consumers use `LedgerClient`, CLI, or REST API.
