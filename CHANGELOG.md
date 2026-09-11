# Changelog

All notable changes to traust-ledger are documented here.

## [0.2.0]

## Changes

- The counterpart to patch_metadata for the event layer: backfills event
  fingerprints (finding_ref -> fp) via attach_identity and re-signs in one
  atomic Backend.mutate. Never overwrites an existing fingerprint (identity
  is a historical observation); returns the count stamped. Lets the harness
  stamp cross-scan identity onto events without writing the layer itself.

## [0.1.1]

## Changes

- **Container image: builder and runtime now agree on the Python minor.** The
  builder stage was `python:3.11-builder` while the runtime was `python:3.12`,
  and the `.venv` built in the builder was copied wholesale into the runtime.
  Native-extension `.so` files are ABI-pinned per minor and the venv's console
  scripts hardcode the builder's interpreter path, so the image shipped with
  missing native modules and an unusable `uvicorn` entrypoint — invisible until
  it ran in a cluster. Both stages are now 3.12, and a deploy invariant asserts
  the minors match so the skew cannot return.

- **Contracts floor raised to 0.1.1.** `LayerEvent.recorded_at` and
  `.occurred_at` are `IsoTimestamp` there, so timestamps are guaranteed RFC
  3339 before they reach this package.

- **Read paths no longer re-implement timestamp parsing.** `_event_dt` dropped
  its timezone normalization (RFC 3339 always carries an offset, and aware
  datetimes compare by instant), and `severity_override.at` is back to a plain
  `occurred_at or recorded_at`. Both were compensating for values the contract
  now rejects.

- **`CorruptStoredEventError` for stored data that breaks a contract
  invariant.** Validation is reachable around — `model_construct` skips it and
  `derive_disposition` accepts already-typed events without re-validating — so
  `_event_dt` still guards, and now names the `event_id`, field, and value
  instead of surfacing a bare `ValueError` as an anonymous 500 over a corpus of
  thousands of layers.

### Upgrading

Contracts 0.1.1 validates timestamps on read as well as write, so a corpus
holding non-conforming values must be migrated **before** deploying this
release (`python3 -m traust.migrations.fix_event_timestamps <root> --apply`).
Otherwise an affected layer stops being readable through `/findings`.

## [0.1.0]

The disposition-ledger kernel: an append-only, Merkle-signed log of
human/machine dispositions against a security-audit report. State is
derived by replaying events — corrections are new events, never edits.
Fixes the domain model, write contract, and integrity scheme shared by
every deployment.
