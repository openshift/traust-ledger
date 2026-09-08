# How the ledger works

### The unit is a layer, one per audit report

A **disposition layer** (`<repo>-findings-layer.json`, schema `layer.schema.json` in
contracts) annotates exactly one security-audit report. It has three parts:

```
metadata      provenance + integrity: audit_report, audit_commit, claim_hashes,
              merkle_root/size/epoch, leaf_format, merkle_root_signature
events        the append-only log
needs_review  statements that did not meet the auto-record bar — no state change
              until a human confirms
```

The audit report itself is **never modified**. The layer is the memory; the report is
the observation it annotates.

### Events are append-only, and a correction is a new event

Nothing in `events` is ever edited or deleted. Disagreeing with an earlier event means
appending a later one. This is what makes the log evidence rather than a cache: state is
*derived* by replaying events, so history survives every change of mind.

Each event carries a disposition on two independent axes:

- **validity** — is the finding real? `confirmed` · `false_positive` · `corrected` · `hardening`
- **resolution** — is it dealt with? `open` · `fix_in_progress` · `resolved` ·
  `partially_resolved` · `risk_accepted` · `regression_introduced`

Keeping them separate is deliberate: *"real, and we accept the risk"* and *"not real"*
are opposite claims, and collapsing them into one field is how false-positive counts get
corrupted.

### Idempotency is structural, not defensive

```
event_id = sha256("<source.ref>|<finding_ref>|<validity>|<resolution>")
```

`compute_event_id`. Re-ingesting the same source produces the same id, so replaying an
import appends nothing. Note the scope: ids are unique **per layer**, so the same
`finding_ref` (`FIND-001`) recurring across hundreds of layers is expected, not a clash.

### Identity travels inside the event

A finding's `fingerprint` is a **pure function** of the finding, computed by the
producer (harness) and carried with the data. The ledger service acts as a backstop
stamper: if a finding arrives without a fingerprint, the service computes it server-side
using the same deterministic recipe and marks the finding `server_stamped: true`.

```
fingerprint = sha256( canon_repo(repo_url) | ";".join(sorted set of canon_path(locations[].path)) | primary_cwe )
```

**The recipe is defined once, in [`finding-identity.md`](finding-identity.md) beside
`traust_ledger/identity.py`** — canonicalization rules, the ASCII-folding decision, strict
mode, and what the fingerprint is *not*. The two properties that matter here: **line
numbers are never hashed** (that is what lets a finding survive edits above it), and a
path canonicalizing to empty is dropped from the set under `ALGO_VERSION` v2.

Events carry `fingerprint` + `fingerprint_algo` (`attach_identity`, `fingerprint_index`).
The algo field is per event, not per layer, because stamps outlive recipes: the live
corpus holds both versions today (198 `v1` against 54,614 `v2`, measured 2026-08-24), and
matching across that boundary means comparing the version too.

Identity is **read, never recomputed**, and never overwritten — an event is a historical
observation, so "at time T this finding's identity was X" stays true. `event_id` is
untouched by it.

Rebaseline mappings (old finding id → its successor) are **also events**
(`make_alias_event`, `aliases_from_events`, `source_type: rebaseline`). They used to live
in a mutable `metadata.finding_aliases` table outside the tree with no verifier — anyone
able to edit it could re-point a `false_positive` verdict at a different finding and the
root would still verify.

### Integrity: the leaf is the whole event

RFC 6962-style Merkle tree over the events. Under **`leaf_format 2`** the leaf is the
canonical JSON of the entire event, so every field — disposition, rationale, actor,
fingerprint, alias — is covered for free. Editing any one of them breaks the root.
(`leaf_format 1` was an `event_id`-only binding and is now an error.)

`metadata` carries `merkle_root`, `merkle_size`, `merkle_epoch`, `leaf_format`,
`pre_merkle_checkpoint` (pinning pre-epoch history), and `merkle_root_signature`.
A signature over the root means only the key-holder can produce a valid ledger state —
which is the enforcement mechanism, not decoration: a component that cannot sign
structurally cannot be the writer of record.

Separately, `claim_hashes` pins each finding's *claim* fields (`compute_claim_hash`,
`CLAIM_FIELDS`) so the annotated report cannot be silently rewritten underneath the layer.

### The write contract

**`LedgerWriter` is the only write path.** Append-only, idempotent by `event_id`, atomic
(tempfile + `os.replace`), optional schema validation, and it enforces the rule that a
human `false_positive` requires an LDAP-verified actor.

**Every writer calls `stamp_and_sign(layer)` immediately before writing.** Skip it and the
root goes stale, which verification reports as a `merkle_root` mismatch **error**. This is
a contract, not a convention — the one code path that mutated a layer and wrote it with a
plain `json.dumps` is a tracked defect.

**A changed root drops the old signature.** When `stamp_merkle_metadata` recomputes a root
that differs from the stored one, it removes `merkle_root_signature` (and its method/format
companions) and returns `True`; `stamp_and_sign` reports that as
`SignAttempt.stale_signature_dropped` whenever it could not re-sign. Keeping the old value
would be worse than having none — an absent signature is a visible gap, a present-but-invalid
one is indistinguishable from tampering. A re-stamp that yields the same root leaves a valid
signature alone. **Writers must print `SignAttempt.warning()`**, which covers both this and a
configured-but-failed signer; a signature that vanishes silently is how a corpus de-attests
without anyone noticing.

### Verification

`verify_merkle_integrity(layer)` returns `IntegrityFinding`s at `Severity.ERROR` or
`WARNING`. Currently errors: absent `merkle_root`, `leaf_format 1` (including absent,
which defaults to 1), root/size mismatch. Proofs are available for external audit —
`inclusion_proof` (this event is in that root) and `consistency_proof` (this root is an
append-only extension of that one).

### Identity recipe fixtures

`tests/fixtures/identity-recipe-vectors.json` pins the recipe with 12 cases, replayed on
every run and regenerable only under a deliberate `ALGO_VERSION` bump. Details, including
what the fixtures do **not** cover, are in [`finding-identity.md`](finding-identity.md).
