# Changelog

## [0.21.4] — 2026-09-08

### Fixed
- `tests/test_service_routes.py` builds the deliberately-invalid Basic
  Authorization header at runtime instead of carrying a base64 literal that
  tripped the public forge's secret-scanning "HTTP basic authentication
  header" detector (openshift/traust-ledger alert #1). The value was a
  throwaway `user:pass`, never a live credential; test behaviour unchanged.

## [0.21.3] — 2026-09-08

### Added
- README License section and `license = "Apache-2.0"` in package metadata,
  matching `LICENSE`.

## [0.21.2] — 2026-09-08

### Fixed
- A test fixture used a real team member's account id as the sample signer;
  neutral placeholder now. `CODEOWNERS` names the `@openshift/traust-maintainers`
  team instead of individual accounts.

## [0.21.1] — 2026-09-08

### Changed
- **`Containerfile` is publishable.** The builder's private-forge shim (a
  hardcoded internal GitLab host, token `insteadOf` rewrite and TLS override)
  is replaced by three opt-in build args — `PRIVATE_GIT_SSH_BASE`,
  `PRIVATE_GIT_HTTPS_HOST`, `PRIVATE_GIT_INSECURE_TLS` — all off by default,
  so a public build resolves the git-tag pins with no credentials and the
  file names no host. The internal pipeline passes the same values it used
  before via `build-args`. Labels are neutral (`traust-ledger`, Apache-2.0,
  source/url on github.com/openshift, version from `ARG VERSION`); the
  Konflux-catalog labels (`com.redhat.component`, `distribution-scope`,
  `release`) and the stale hardcoded `version="0.12.2"` are gone.

## [0.21.0] — 2026-09-08

### Added
- **Employee-directory cross-check on every path** (`traust_ledger.auth.directory`).
  `LEDGER_DIRECTORY_COMMAND` names a deployment command run as
  `<command> <identity>` that prints `RESULT uid=… status=…`; only `active`
  passes and is stamped as `employee_status`. Applied after token
  verification by both the REST `ActorResolver` and the in-process
  `LedgerClient` (`_actor()`), so a countersign or any SDK write by a
  terminated account is refused before the writer is reached. Unset → no
  cross-check (the default for adopters without a directory). Misconfigured
  (program missing) fails at construction; unrunnable/non-zero/no RESULT
  line is `unavailable`, a refusal. Machine actors are never cross-checked.
  Until now the port existed only on the REST resolver and nothing wired it;
  the harness ran its own LDAP script and bypassed the SDK instead.
- `LedgerClient.actor()` — public: the verified actor this client writes as.
- `LedgerClient(directory=...)`: `None` = env, `False` = explicitly none, or
  an `EmployeeDirectory` object.
- `EmployeeDirectory` protocol moved to `traust_ledger.auth.directory`
  (re-exported from `service.identity.ports`); `ScriptDirectory`,
  `load_directory`, `apply_directory`, `DirectoryRefusedError`,
  `DirectoryUnavailableError` exported from `traust_ledger.auth`.

## [0.20.2] — 2026-09-07

### Changed
- **README module reference lists the full public surface.** The table named
  a subset of what each documented module exports; the drift check's
  export audit counted 36 omissions across `api.events`, `api.integrity`,
  `api.reports`, `api.disposition`, `api.identity`, `handlers`, `service`,
  and `client`. Every exported name now appears with a one-line meaning.
- **`traust_ledger.client` declares `__all__`** (`LedgerClient`, `LedgerError`,
  `resolve_env_token`). Without it the module's public surface was, by
  Python's rules, every name it imports — backends, the writer, signing
  config, handler functions — none of which the client is meant to expose.
  Star-imports and the export audit now see the intended three.

## [0.20.1] — 2026-09-07

### Fixed
- **The integrity CronJob invoked a module that does not exist.**
  `deploy/cronjob.yaml` ran `python -m traust_ledger.cli.verify`; there is no
  such module (the 2026-09-02 security review filed this as LC-6 under the old
  package name, and the rename carried it forward). It now runs
  `python -m traust_ledger.cli verify --all`, the CLI's Merkle sweep, so the
  every-6-hours verification actually executes. `docs/deploying.md` matches.
- **CODEOWNERS covered nothing under `src/`.** Its package pattern was
  `/traust_ledger/`, a path that predates the `src/` layout, so the two-person
  rule on ledger code was not enforced. Now `/src/traust_ledger/`.
- Stale pointers from the restructure: the identity module's prose-contract
  reference (`docs/identity.md` → `docs/finding-identity.md`), and the
  recipe-vectors generator's docstring, which named its own predecessor
  (`gen_identity_golden_vectors.py`), the pre-`src/` module path, and the
  contracts test by its old submodule path.

## [0.20.0] - 2026-09-06

### Changed

project references not refer to this as traust-ledger
bumped traust-contracts

## [0.19.7] — 2026-09-06

### Changed
- **Sibling dependency URL follows the project rename.** The `ai-security-contracts`
  git pin now points at `hybrid-platforms-sec/traust-contracts.git` (the GitLab
  project path was renamed from `ai-security-contracts`). Same tag `v1.0.0`, same
  commit; only the source URL changes. The Konflux `.tekton` repo annotations
  point at the renamed `traust-ledger` path.

## [0.19.6] — 2026-09-03

### Fixed
- **`ci/setup-uv.sh` no longer hardcodes the forge hostname.** The
  `insteadOf` rewrite that maps `uv.lock`'s `ssh://` sibling-dep URLs to
  authenticated HTTPS now takes the host from `$CI_SERVER_HOST`, which
  GitLab sets on every job, instead of a literal. An internal hostname
  compiled into a tracked file is a disclosure, and the value is
  deployment identity the environment already carries.
  The script is CI-only (it already requires `$CI_JOB_TOKEN` and a
  runner CA), so it now fails closed when `$CI_SERVER_HOST` is unset
  rather than installing a rewrite that matches nothing and failing later
  on an opaque auth error. Assumes the sibling deps live on the same
  GitLab as the pipeline — noted in the script, because a dep on another
  forge would need its own rewrite.

## [0.19.2] — 2026-09-02

### Fixed
- **Stamp `fingerprint_algo` uniformly across all write paths.** Three gaps
  where `fingerprint_algo` was not persisted on events:
  1. Human-lane events (countersign, severity) via `POST /events` — built
     with `finding_ref` only, no fingerprint resolution from layer history.
  2. Birth events (vuln_scan, regression, impact) via `POST /events` —
     passthrough with fingerprint but no algo stamp.
  3. CLI `ledger submit` — bypassed `_stamp_fingerprint_algo_on_event`.

  The stamp is now centralised in `LedgerWriter._prepare_event`, and human-
  lane events resolve `finding_ref → fingerprint` from existing layer events
  in the `_before_append` callback. No SDK changes required.

### Changed
- **Dependency: `traust-contracts` rolled to v1.0.0.**

## [0.18.7] — 2026-09-01

### Added
- **Submit stamps `fingerprint_algo` on events.** Events arriving with a
  `fingerprint` but no `fingerprint_algo` are stamped with the current
  `ALGO_VERSION`, making traust-ledger the sole authority for the fingerprint
  algorithm version.
- **`LedgerClient.patch_metadata(layer_id, updates)`** — merge metadata keys
  and re-sign atomically via `Backend.mutate`.
- **`LedgerClient.create(layer_id)`** — bootstrap an empty layer (unsigned).
- **Backend conformance tests** for `mutate`, rollback, and I2 signing parity
  across `FileBackend` and `DbBackend`.

### Changed
- **`LedgerClient.sign()` is now atomic.** Uses `Backend.mutate` +
  `finalize_layer` — one lock, one write. Half-written or unsigned layers are
  structurally impossible.
- **`signing_required` resolved from env.** `LAAS_SIGNING_REQUIRED` is read
  by `LedgerClient` (previously only reachable from CLI). Also accepted as a
  constructor kwarg.
- **`LedgerClient` resolves `SigningConfig.from_env()` internally** when no
  `signing_config` is passed — callers no longer import the internal type.
- **`SigningFailedError` is legible.** Names the layer, the cause, the remedy,
  and confirms nothing was written.
- **`ledger sign` CLI** uses `backend_from_env()` instead of hardcoded
  `FileBackend`, restoring DB backend parity.

### Fixed
- **Two-person gate fail-open** (`gates.py`). `_parse_event` no longer silently
  drops malformed events — unparseable events are treated as present-and-unknown,
  blocking the gate instead of letting a single human bypass it.

### Removed
- **`Authenticator` shim** — no external consumers; use `resolve_auth()` or
  `TokenVerifier` directly.
- **Dual-source `VerifierConfig`** — setting both `jwks_url` and `jwks_path`
  now raises `ValueError`. Use `resolve_auth()` for single-source configs.

## [0.18.6] — 2026-08-31

### Changed
- **`LedgerClient(token)` → `LedgerClient(token=None)`** — token is now
  optional. Omit it and the constructor resolves auth from the env chain
  (`LAAS_TOKEN` → stored creds → auto-mint), same as `from_env()`.
  Consumers no longer need `resolve_auth()` or `from_env()` ceremony.
- **Constructor split into `_resolve_identity` / `_resolve_backend`** —
  each owns its concern; the constructor is a two-liner.
- **`from_env()` is now a thin alias** for `LedgerClient()`.

## [0.18.5] — 2026-08-31

### Changed
- **Unified auth: builder→strategy pattern.** `resolve_auth()` is the single
  coupled builder for CLI/SDK — pairs a token with its matching verifier in one
  step. REST continues to use `OIDCAdapter.from_config()` unchanged.
- **`TokenVerifierPort` protocol** replaces concrete `TokenVerifier` in public
  signatures (`ResolvedCredential.verifier`, `_TrustEntry.verifier`), enabling
  test doubles and alternative implementations.
- **Shared `claims_to_actor()`** extracts JWT-to-`LayerActor` mapping into
  `traust_ledger.auth.claims`, eliminating duplication between `TokenVerifier`
  and `OIDCAdapter`.
- **`CredentialStore` protocol** decouples `config.py` from CLI imports.
  `resolve_auth(store=...)` accepts an injectable credential backend.
- **`verifier_for_token()`** (previously `_verifier_for_token`) is now public
  for callers that have a token but not its verifier.

### Added
- **`IdentityClaimsError`** — subclass of `TokenVerificationError` for
  claims-mapping failures (empty email, no identity claims) vs crypto failures
  (expired, bad signature). Existing `except TokenVerificationError` catches both.
- **`TokenVerifier`, `IdentityClaimsError`, `CredentialStore`,
  `verifier_for_token`** exported from `traust_ledger.auth`.
- **893-line `test_unified_auth.py`** covering claims mapping, protocol
  conformance, `ResolvedCredential.verify()`, OIDCAdapter delegation,
  LedgerClient paired verifier, Authenticator deprecation, CLI integration,
  and mock-OIDC e2e for both SDK and CLI flows.

### Deprecated
- **`Authenticator`** — emits `DeprecationWarning`, will be removed in 0.19.x.
  Use `resolve_auth()` or `TokenVerifier` directly.
- **Dual-source `VerifierConfig`** (`jwks_url` + `jwks_path` together) — emits
  `DeprecationWarning`. `resolve_auth()` always builds single-source configs.

### Fixed
- **Phantom `api.signing` docstring** — removed reference to nonexistent
  `traust_ledger.api.signing` module from `api/__init__.py`.

## [0.18.4] — 2026-08-31

### Fixed
- **OIDC is primary again; local is an issuer-matched fallback.** 0.18.3 let an
  explicit `ledger auth local` outrank ambient OIDC settings, which inverted the
  trust relationship — a self-signed local credential displacing an externally
  attested provider. Underneath, `TokenVerifier` loaded its key sources with
  `elif`, so the two could never coexist and a local JWKS on disk shadowed a
  configured provider outright.

  Both sources are now loaded, and the *token's own issuer* selects between them:
  an OIDC token is always checked against the provider, and a token carrying
  `iss: local` is checked against the local JWKS instead of being rejected as
  "wrong issuer". The issuer claim is read unverified and authorises nothing — a
  forged `iss: local` is merely routed to the local keys, where it fails to
  verify (covered by test). Explicit callers (the REST service) are never handed
  local key material.

### Added
- **An import-graph tripwire in `tests/conftest.py`.** Re-importing a package
  does not rebind submodule attributes on its parent, so restoring `sys.modules`
  is insufficient: `traust_ledger.auth` was twice left without `.config`/`.flows`,
  and unrelated later tests failed resolving dotted monkeypatch targets with an
  AttributeError pointing at the wrong file. The tell was a test passing alone
  and failing in the suite. This fails the test that causes the damage, naming it
  and the remedy (do such work in a subprocess).

## [0.18.3] — 2026-08-31

### Fixed
- **An ambient `LEDGER_OIDC_ISSUER` stranded locally-minted tokens.**
  `_local_fallback()` was reachable only when neither `LEDGER_OIDC_ISSUER` nor
  `LEDGER_OIDC_JWKS_URL` was set, so an issuer exported for an unrelated host —
  or simply left in a shell — sent verification to OIDC discovery, and a token
  carrying `iss: local` cannot validate against a provider's JWKS. On an install
  without the `cli` extra the symptom was an HTTP-client error raised during a
  *write*. Running `ledger auth local` records `active_server = "local"`; that
  choice now outranks the environment. Callers passing configuration explicitly
  (the REST service) are never redirected to local.
- **`PyJWT[crypto]` no longer duplicated** in the `service` and `cli` extras. It
  became a core dependency in 0.17.2; two copies can drift apart. A test asserts
  it stays core-only.
- **Test isolation, properly this time.** The httpx2-absence check deleted and
  re-imported `traust_ledger.auth*`; restoring `sys.modules` does not restore the
  parent package's submodule attributes, so `traust_ledger.auth` was left without
  `.config`/`.flows` and unrelated tests failed to resolve monkeypatch targets.
  It now runs in a subprocess, which cannot leak.

## [0.18.2] — 2026-08-31

### Fixed
- **A missing token could surface as a filesystem error.** `resolve_env_token`
  (0.17.2) falls back to the CLI credential chain, which touches disk —
  `config_dir()` mkdirs on every call and the auto-mint writes a keypair. Where
  there is no writable HOME (a container, a cron job, CI), `from_env()` raised
  `OSError: Read-only file system: '/.config'` instead of the auth error it
  means, naming neither the cause nor the fix. Before 0.17.2 this path raised a
  clean `LedgerError`, so it was a regression. An unreachable credential store is
  now treated as an empty one.

## [0.18.1] — 2026-08-31

### Fixed
Four defects in 0.18.0's machine identity, found on review before it was used.
All the same shape: the **kind** was re-derived from the immediate invocation
while the **identity** was restored from remembered state, so ordinary use
silently downgraded automation to a named person — the misattribution machine
identity exists to prevent, arriving by the path least likely to be watched.

- **`ledger auth local` with no arguments downgraded a machine identity to
  human** and lower-cased the version string it names. This is the documented
  refresh — the command even prints "refreshed". The remembered kind is now
  inherited, and `--human` added to downgrade deliberately.
- **`_auto_mint_local_token` always minted human.** It is the fallback
  `resolve_token` reaches when a stored credential *expires*, so a seven-day-old
  machine identity flipped mid-campaign. It now follows the remembered kind, or
  `LEDGER_LOCAL_MACHINE=1`.
- **`ledger auth service-account` reported `Kind: machine` for an opaque token**
  whose claims it could not read — a false assurance about the one thing being
  checked. Unreadable claims now report `unknown`.
- **Unguarded `response["access_token"]`** after config had already been saved.

## [0.18.0] — 2026-08-31

### Added
- **Machine identity, in both modes.** Automation had no way to sign as itself.
  `mint_local_token` always set `sub` *and* `email`, and
  `TokenVerifier._claims_to_actor` reads `machine` only when the machine claim
  (`azp`) is present and the identity claim (`email`) is absent — so every
  locally-minted token was a **human** actor by construction, with no flag to
  change it. A scheduled or replayed emission therefore signed as whoever ran it:
  replaying July's triage verdicts stamped a named person as a `human` actor onto
  `validity: confirmed` findings they had never seen, while the events those runs
  originally wrote carried `{"kind": "machine", "identity": "triage/<version>"}`.

  - `ledger auth local --machine --identity triage/0.32.0` — mints `azp` and omits
    `email`. For operator-run backfills on a trusted host. Machine identities are
    not case-folded: a version string is not an address.
  - `ledger auth service-account` + `ClientCredentialsFlow` — the OAuth2
    `client_credentials` grant, for the ongoing pipeline. The secret is read from
    `--client-secret-file` or `LEDGER_OIDC_CLIENT_SECRET`, never argv. If the
    provider returns a token carrying an identity claim it warns at acquisition,
    because such a token verifies as *human* and the misattribution is otherwise
    invisible until it is already recorded.

  Human remains the default; omitting the flag changes nothing.

### Fixed
- **Test isolation in `test_auth_optional_httpx.py`.** It deleted and re-imported
  `traust_ledger.auth*` without restoring the subtree, leaving a partially imported
  package that broke unrelated monkeypatch targets later in the same session.

## [0.17.3] — 2026-08-28

### Fixed
- **`pyproject.toml` version was left at 0.17.1 when 0.17.2 shipped.** The
  version lives in both `VERSION` and `pyproject.toml`; bumping only the former
  publishes a tag whose distribution metadata reports the previous release, so
  `traust-ledger>=0.17.2` reads as unsatisfied and drift checks show a skew that
  syncing cannot clear. Same failure as 0.13.0. A test now asserts the two
  files agree, so a one-sided bump fails the suite instead of the release.

## [0.17.2] — 2026-08-28

### Fixed
- **A plain `traust-ledger` install could not append an event.** Authentication
  sits on the path of every write (`LedgerClient` → `Authenticator` →
  `auth.config` → `auth.discovery`), but two of its dependencies were reachable
  only through optional extras, so any consumer that installed `traust-ledger`
  without them died on import:

      ModuleNotFoundError: No module named 'httpx2'
      ModuleNotFoundError: No module named 'jwt'

  This took out `traust-engine`'s `LedgerService` and every harness call site
  behind it, including writes using a locally-minted token that makes no
  network call at all.

  - `PyJWT[crypto]` moves from the `cli`/`service` extras into core
    `dependencies` — verifying any token, local or OIDC, requires it.
  - `httpx2` stays optional and is now imported lazily inside the functions
    that actually reach an OIDC provider (`traust_ledger.auth._httpx.http()`),
    which raises a message naming `traust-ledger[cli]` instead of the bare
    `ModuleNotFoundError`.

### Added
- **`traust_ledger.client.resolve_env_token()`** — SDK token resolution now
  follows the same chain as `ledger auth token`: `LAAS_TOKEN`, then
  `LEDGER_TOKEN_PATH`, `LEDGER_TOKEN`, stored `ledger auth login` credentials,
  and a locally-minted JWT when `LEDGER_LOCAL_IDENTITY` is set. Previously
  `from_env()` read `LAAS_TOKEN` alone, so a developer who had run
  `ledger auth local` still could not write. `from_env()`'s error now names the
  remedies rather than only reporting that a token is absent.

## [0.17.1] — 2026-08-27

### Fixed
- **`LedgerClient._actor()` strict identity verification.** Uses
  `build_verifier_config()` for the full OIDC env → local JWKS fallback;
  raises `LedgerError` if identity cannot be verified (verify-or-refuse
  contract, matching CLI and REST entry points).
- **`_append_many` dedup tracking.** Returns only newly-appended event IDs,
  not pre-existing dupes — fixes dedup count for `submit_events` callers.

### Changed
- Removed `resolve_review_item` and `review_item_key` from public API
  (`traust_ledger.api.events`). Resolution goes through `LedgerService` →
  `LedgerClient.resolve()`.
- Added `stamp_artifact_digests` to `traust_ledger.api.reports`.
- Added `event_ids` and `queue_added` fields to `SubmitResponse` model
  and OpenAPI spec.

### Added
- `TestLedgerClientActorGate` tests (garbage, valid local, expired token).
- `test_e2e_merkle_pipeline.py` moved here from `traust`
  (tests traust-ledger internals).

## [0.17.0] — 2026-08-27

### Added
- **`traust_ledger.api` — public pure-computation API surface.** Modules for
  events, identity, integrity, disposition, reports, findings, and verify.
  Consumers import from `traust_ledger.api.*` instead of `_internal`.
- **`LedgerClient` — in-process Python SDK** (`traust_ledger.client`). Symmetric
  with the CLI and REST API: `.sign()`, `.submit()`, `.resolve()`,
  `.query_findings()`, `.verify()`. Identity derived from bearer token at
  construction time.
- **Local auth** (`traust_ledger.auth.local`). Frictionless keypair generation
  and JWT minting for CLI adoption without an external OIDC provider.
- **`traust_ledger.handlers/`** — handlers extracted from `service/` so
  `LedgerClient` and REST share the same implementation.
- **`traust_ledger.config`, `models`, `errors`, `paths`, `constants/`** — lifted
  to package root for shared access across client, CLI, and service.
- **`docs/consumer-integration.md`** — integration guide for traust-engine
  and other downstream consumers.

### Fixed
- **`ServiceConfig` no longer requires `pydantic_settings` at import time.**
  `ServiceConfig` is now a plain `pydantic.BaseModel`. A new `ServiceSettings`
  in `traust_ledger.service.settings` extends it with `BaseSettings` for
  env-auto-loading; only the REST app imports it. Consumers that depend on
  bare `traust-ledger` (no `[service]` extra) can now import `LedgerClient`
  without pulling in `pydantic-settings`.
- **`LedgerClient.sign()` no longer rejects layers with no events.** It was
  calling `load_layer()`, which validated content; now loads directly from
  the backend, matching the CLI and REST behavior.
- **REST `sign_layer_endpoint` called a non-existent `write_layer()` method.**
  Replaced with `backend.store(path, layer)` for persistence and
  `backend.load(path)` for reading (consistent with `LedgerClient.sign()`).

### Changed
- **All three sign paths converge on `sign_handler.sign_layer()`.** CLI, REST,
  and `LedgerClient` all invoke the same handler. The CLI passes explicit
  `SigningConfig` from its arguments; REST and `LedgerClient` derive credentials
  from `ServiceConfig`. Load/store uses the backend directly in all three.
- **CLI uses `config_from_env()`.** CLI commands build `ServiceConfig` from
  `LAAS_*` env vars without importing `pydantic_settings`.

## [0.16.0] — 2026-08-26

### Added
- **Trust multiple OIDC issuers at once.** A new `LAAS_OIDC_TRUST` setting takes
  a JSON array of `{issuer, jwks_url, audience}` entries; a bearer token is
  validated against the entry whose issuer matches its `iss` claim. This lets
  the ledger accept tokens from more than one source simultaneously — for
  example a browser SSO provider for human callers and the cluster
  ServiceAccount issuer for machine callers — each with its own signing keys
  and audience. When `LAAS_OIDC_TRUST` is unset, the existing single
  `LAAS_OIDC_ISSUER` / `LAAS_OIDC_JWKS_URL` / `LAAS_OIDC_AUDIENCE` settings are
  used unchanged, so current deployments are unaffected. Tokens from issuers
  not in the trust list, or with the wrong audience for their issuer, are
  rejected.
- **`POST /v1/ledger/layers/{layer_id}/submit`** — batch-submit pre-formed
  events and queue items atomically. Stamps caller identity on every event.
- **`ledger submit` CLI command** — local equivalent of the REST batch submit.
- **`POST /v1/ledger/fingerprint`** — REST endpoint for finding fingerprint
  computation (parity with CLI).
- **`ledger event`, `ledger countersign`, `ledger resolve`** CLI commands for
  individual event submission, countersigning, and review-item resolution.
- **CLI identity system** — `ledger login` / `ledger auth` with OIDC device
  code flow, token caching, and refresh.

### Changed
- **Internal modules moved to `_internal/`.** `writer`, `disposition`, `events`,
  `identity`, `hashing`, `reports`, `integrity`, `backends` are now under
  `ledger_core/_internal/`. External consumers must use the CLI or REST API.
- **`EventIdMismatchError` surfaces as 422** in both REST handlers and the CLI
  (previously escaped as a 500 from the writer's `ValueError`).
- **Base deploy configmap defaults to `oidc`** (was `apikey`). Requires
  `LAAS_OIDC_JWKS_URL` or `LAAS_OIDC_TRUST` to start.

### Removed
- **API key identity provider** (`LAAS_IDENTITY_PROVIDER=apikey`). OIDC
  client-credentials or Kubernetes projected SA tokens cover machine auth.
  The `LAAS_APIKEY_KEYS` and `LAAS_APIKEY_HEADER` config fields are gone.
- **Static identity provider** and **LDAP cross-check adapter** — dead code
  superseded by the pluggable OIDC adapter.
- **`traust_ledger.converters`**, **`traust_ledger.corpus`**, **`traust_ledger.state`**,
  **`traust_ledger.projection`** — removed modules that belonged in traust-engine.

## [0.15.4] — 2026-08-26

### Fixed
- **Enterprise Contract no longer rejects every prefetched RPM.** `rpms.in.yaml`
  declared the content origin as `repoid: public-hummingbird`. Hermeto copies
  that id verbatim into the SBOM as `repository_id`, and EC's
  `rpm_repos.ids_known` rule matches it exactly against its
  `known_rpm_repositories` list — which carries only the arch-qualified ids
  (`public-hummingbird-x86_64-rpms` and siblings). The bare label matched
  nothing, so all 74 packages pinned in `rpms.lock.yaml` were reported as
  coming from an unknown or disallowed repository. Measured on the
  `source-code-intelligence` group snapshot of 2026-08-26: 10 violations
  reported with 64 further collapsed, every one of them
  `rpm_repos.ids_known`, and every other component in the snapshot clean.
  `repoid` is now the arch-qualified id in both `rpms.in.yaml` and
  `rpms.lock.yaml`, with the constraint written down beside it so a
  regeneration does not quietly reintroduce the short label.

  The id is a label only — `baseurl` is what is actually fetched — so no
  package, URL, or checksum changes.

  This blocked the release gate for the whole application, not just this
  service: the group-snapshot EC run validates every component, so the
  failure appeared on unrelated Konflux/MintMaker pull requests in the six
  `source-code-intelligence*` GitHub repositories, none of which could merge.

## [0.15.3] — 2026-08-26

### Added
- **`deploy/overlays/oidc/`** — the deployment posture as a kustomize target:
  `kubectl apply -k deploy/overlays/oidc/`. Sets `LAAS_IDENTITY_PROVIDER=oidc`,
  supplies the three OIDC settings the provider refuses to start without, and
  `LAAS_SIGNING_REQUIRED=true` — an overlay that authenticates properly and
  leaves writes unsigned is half a posture.
- `LAAS_LDAP_BIND_DN` / `LAAS_LDAP_BIND_PASSWORD` documented in
  `secret.example.yaml` with the reason attached: anonymous search is refused by
  many directories, which reports as `auth_failed` rather than as a claim about
  a person.

### Notes
- Base keeps `LAAS_IDENTITY_PROVIDER: "static"` deliberately — a bare
  `kubectl apply -k deploy/` must boot on minikube with no issuer, which
  `test_configmap_bootstraps_without_oidc` pins. It now says so and points at the
  overlay, instead of leaving the dev provider looking like a recommendation.
- Written against `auth_mode` and rebased onto the provider registry (0.15.1),
  which renamed the key to `LAAS_IDENTITY_PROVIDER`. The overlay and its tests
  use the new name; nothing here reintroduces the old one.

## [0.15.2] — 2026-08-25

### Fixed
- **The container build no longer times out installing build-time RPMs.**
  The hardened-image migration added `microdnf install git ca-certificates`
  to the builder stage, which fetched RPMs live from `packages.redhat.com`;
  that host is throttled in the Konflux build network and every fetch timed
  out (`Curl error 28`), failing the build for `main` and every branch. The
  RPMs are now prefetched through Hermeto (`rpms.in.yaml` / `rpms.lock.yaml`
  with `prefetch-input` set to `rpm`), so they come from the package proxy
  instead of a live download. The build stays non-hermetic because the
  builder still fetches the internal git dependency over the network until
  that repository is public.

## [0.15.1] — 2026-08-25

### Added
- **Pluggable identity provider registry.** `@register("name")` decorator +
  `build_provider(config)` selects adapter by `LAAS_IDENTITY_PROVIDER` env var.
  Built-in: `oidc`, `apikey`, `static`.
- **API key adapter** — `LAAS_IDENTITY_PROVIDER=apikey` for machine-to-machine
  auth via configurable header (`LAAS_APIKEY_HEADER`, `LAAS_APIKEY_KEYS`).
- **`WWW-Authenticate: Bearer`** header on all 401 responses (RFC 6750).
- Startup warning when OIDC audience validation is skipped.

### Fixed
- **`oidc_machine_claim` was dead code.** The `azp` claim (configurable) is now
  checked first: present + no identity claim → machine. Previously, service
  accounts with an email were misclassified as human.
- **Empty/whitespace identity** no longer lands in the ledger — rejected with 401.
- **Resolver mutation** — `model_copy(update=...)` replaces in-place
  `actor.employee_status = status`, preventing mutable state leakage.

### Removed
- `OIDCVerifier` alias, `IdentityVerifier` alias, `BEARER_PREFIX` constant,
  `TwoPersonMissingError` (never raised), `BearerVerifier` class — all dead code.
- `auth_mode` config field (superseded by `identity_provider`).

### Changed
- `docs/auth.md` split into `service-identity.md` (API auth) and
  `ledger-integrity.md` (Merkle/signing). `auth.md` is now an index.
- `docs/identity.md` renamed to `finding-identity.md` for clarity.
- All protected routes use `resolve_actor` (writes) or `require_identity` (reads).
- Config sections clearly separate service-layer identity from signing OIDC fields.

## [0.15.0] — 2026-08-25

### Fixed
- **`LDAPDirectory` reported every failure as `not_found`.** A refused search and
  an unreachable server both returned the status that means "this person does not
  exist". Measured against the real directory: an anonymous search returns
  `48 inappropriateAuthentication: Anonymous access is not allowed` with zero
  entries, so reading only `conn.entries` reported an **active employee** as
  `not_found` — and `ActorResolver` raises `InvalidAuthError` on anything but
  `active`, so the human was refused with a false explanation. Now returns
  `auth_failed` (bind or search refused) and `unavailable` (server unreachable);
  `not_found` is reserved for a successful search that matched nothing. Every
  non-`active` status still fails closed — the change is whether the operator is
  told the truth about why.

### Added
- `LAAS_LDAP_BIND_DN` / `LAAS_LDAP_BIND_PASSWORD` — a service credential for the
  directory search. Anonymous otherwise, which many directories refuse.

### Notes
- `docs/auth.md` now states the identity model plainly: **OIDC proves who the
  caller is; the employee directory is an optional cross-check** that answers a
  narrower, Red Hat-shaped question. `ActorResolver` already accepted
  `directory=None` and `_build_resolver` already wired LDAP only when configured
  — that was true and undocumented, which is how it read as mandatory.

## [0.14.0] — 2026-08-25

### Added
- **`resolve_review_item(layer, ...)`** — the rules from `resolve_needs_review`,
  extracted as a pure function over a layer dict. A caller that already holds the
  layer and writes it itself cannot go through `LedgerWriter` without writing
  twice; `traust`'s `countersign` is exactly that caller, and it is
  the reason 16,706 items sat `pending` while their decisions were recorded as
  events — the human acted, and nothing closed the queue entry. Sharing the
  function keeps the confirmed-requires-an-event and rejected-requires-a-note
  rules in one place instead of re-implemented beside each writer.
  `LedgerWriter.resolve_needs_review` now wraps it under the lock.

## [0.13.2] — 2026-08-25

### Fixed
- **`resolve_needs_review` could not reach a pending item shadowed by a resolved
  twin.** It broke on the first item matching the key; if that one was already
  closed it returned `False` and the pending duplicate stayed unreachable
  forever. The key is not unique — a review item has no id in the schema, so two
  statements about the same finding, from the same source, with the same quote
  collide. The corpus has them: **79 `rebaseline_mapping` items across 18 layers**
  survived a full bulk-close pass because of this. Now matches the first PENDING
  item with that key.

## [0.13.1] — 2026-08-25

### Fixed
- **0.13.0 is broken — do not pin it.** Its tag carries `pyproject.toml` still
  reading `0.12.1`, so the package built from it reports the wrong version and a
  `traust-ledger>=0.13.0` constraint cannot resolve against it. Cause: VERSION had
  drifted to 0.12.2 while pyproject sat at 0.12.1 (the same split fixed once in
  3e3ee7b), and the release edit targeted the value in VERSION rather than the
  one in pyproject, so the substitution silently matched nothing. Both files now
  read 0.13.1. Use `make bump`, which writes both and refuses across a split,
  instead of editing either by hand.

## [0.13.0] — 2026-08-25

### Added
- **`LedgerWriter.resolve_needs_review`** — the queue had an append and no exit.
  Items were written `pending` and nothing anywhere could move them: across the
  live corpus, **16,706 of 16,740 review items are still pending**, some for
  months, and `resolution_note` appeared in no source file. Items are addressed
  by `review_item_key`, now shared with `append_needs_review` so the two cannot
  drift into a queue nothing can close.
  Enforces the two rules `layer.schema.json` states and nothing implemented:
  `confirmed` requires the corresponding event to already be in the layer (a
  confirmed item asserts a determination the ledger must actually hold), and
  `rejected` requires a `resolution_note`. A decision is terminal; re-open by
  queueing a new item.
  Takes the backend lock, validates before writing, and involves **no signing**:
  `needs_review` is not an event, so it is outside the Merkle tree and outside
  `merkle_signature_payload` — pinned by a test asserting the signature survives.
- **`submit_report` auto-resolves `needs_identity` on a stamped re-submission.**
  The ordinary end of an identity quarantine is the finding coming back stamped;
  that should not need a human. Resolution happens *after* the events append, so
  the confirmed-requires-an-event rule holds, and a failure leaves the item
  pending with a warning rather than closing it on a determination the ledger
  does not have. Only stamped, audit-shaped findings qualify — a still-unstamped
  finding is being withheld again on that very submission.

### Notes
- This does not prevent findings without fingerprints; producers stamping does.
  It cleans up after the case where one slips through.

## [0.12.2] — 2026-08-25

### Fixed
- Pull the hardened Python base image from `registry.access.redhat.com`
  instead of `registry.redhat.io`. The latter requires Red Hat Customer
  Portal credentials the Konflux build does not have, which broke the
  release build; the public hardened-images registry needs no auth and is
  the one the Enterprise Contract base-image policy requires.

## [0.12.1] — 2026-08-25

### Fixed
- **The `HARNESS_SIGNING_*` env family works again.** 0.11.0 renamed it to
  `LAAS_SIGNING_*` with no alias, and the failure was silent and fail-OPEN in
  both directions at once: a caller exporting `HARNESS_SIGNING_KEY_PATH` — the
  harness, its four signing migrations, every operator runbook and every CI job —
  configured **no signer at all** and wrote unsigned layers, while
  `HARNESS_SIGNING_REQUIRED=1`, the guard that exists to catch exactly that
  ("deleting the signature is not a downgrade path", self-audit -006), stopped
  being read by the same rename. A renamed fail-closed switch defaults to off.
  Measured before the fix: with `HARNESS_SIGNING_KEY_PATH` set,
  `SigningConfig.from_env().key_path` was `None`.
  Every signing setting now reads `LAAS_SIGNING_*` first and falls back to
  `HARNESS_SIGNING_*` (`signing_env`), so a mixed environment converges on the
  current name without a flag day. Caught by traust's
  `test_e2e_ci_merkle_pipeline` during the pin roll, not by anything here.

## [0.12.0] — 2026-08-25

**A receiver must not invent identity** (ledger-plan D-open-2, decided 2026-08-25).

### Removed
- **The server-side fingerprint backstop** from 0.11.0. A fingerprint is
  `sha256(canon_repo | sorted paths | primary CWE)`, and the producer holds all
  three at audit time while a receiver holds only what the envelope carries. Two
  measured failures: with `metadata.repository` absent, findings in unrelated
  repositories sharing a path and CWE both hash to `45cb7c4c…`; and since no
  converter here reads `locations` or `cwes` — the service ingests verdict rows,
  which have never carried either — the backstop hashed them into
  `sha256(repo | "" | CWE-0)`, one identity for **every** row in a repository
  (`a7b60f7f…` for two different triage verdicts). `server_stamped: true` did not
  mitigate it: findings are `additionalProperties: false` in the schema, and the
  flag reached no event.

### Added
- **`needs_identity` quarantine.** A finding that carries identity inputs
  (`locations`/`cwes`) but no `fingerprint` is withheld from conversion and
  queued as a `needs_review` item. The submission is still accepted. Verdict rows
  pass through exactly as before 0.11.0 — their identity belongs to the baseline
  finding they reference, and `attach_identity` stamps their events from it later.
- **`LedgerWriter.append_needs_review`.** The queue had no write path: converters
  have always produced `needs_review` items and `submit_report` counted them in a
  debug log and discarded them. Idempotent, and not events, so it can neither move
  a Merkle root nor invalidate a signature.
- **6e's columns are populated.** `materialized_findings.fingerprint` takes the
  finding's most recent stamp (newest-wins: identity is a historical observation
  and events are never re-stamped), and `orphan` is baseline membership read from
  `metadata.claim_hashes`. Both stay nullable and an unknown never becomes a
  `False` — 27.6% of rows have no fingerprint available at all, and a layer
  without claim_hashes cannot answer the orphan question.

### Fixed
- `load_layer` treated "no events" as 404, so a submission whose findings were all
  withheld returned `200 accepted` and then `404` on read. A layer holding only
  queued statements exists.

### Changed
- Requires contracts **0.7.0** (the `needs_identity` queue reason).

## [0.11.0] — 2026-08-25

### Added
- **Server-side fingerprint backstop.** Report handler computes fingerprints for
  unstamped findings using `identity.fingerprint()`, marks `server_stamped: true`.
- **Query CLI** with full endpoint parity (`layers`, `layer`, `findings`, `events`,
  `verify`) using decorator-based command registry and pydantic models.
- **`traust_ledger.state`** — `current_state(backend, data_dir, layer_id)` read accessor
  over existing `Backend` protocol.
- **`fingerprint` and `orphan` columns** on `materialized_findings` (nullable, schema only).
- **Portable secret overlays** in `deploy/overlays/` (k8s-secret, vault-csi, external-secrets).
- **OpenAPI spec** persisted at `docs/openapi.json` and `docs/openapi.yaml`.

### Fixed
- Event handler: fail-closed on missing validity for false-positive gate.
- Materializer: `LAAS_MATERIALIZE_URL` env var takes precedence over `--to` (credential safety).
- Dead code removal (`RPM_CATEGORY_RX`).

## [0.10.0] — 2026-08-21

### Added
- **Artifact digests and signature format 4** (plan R1). `stamp_artifact_digests`
  records `metadata.artifact_digests` (filename → SHA-256) for every artifact sharing
  a layer's base. Format 4 signs a digest over the map. `check_artifact_digests`
  reports mismatches, unrecorded files, and missing files.
- Canonical fingerprint definition in `docs/identity.md`.
- Requires `traust-contracts>=0.6.0`.

## [0.9.0] — 2026-08-21

### Added
- **`traust_ledger.corpus`** — unique layer IDs for nested findings trees, fixing
  19.4% silent row loss in the projection (347 colliding stems, 6,960 overwritten rows).

### Fixed
- Signing/event refactors from `feat/ledger-service` stash landed.

## [0.8.5] — 2026-08-21

### Fixed
- **A digest change now drops a format-3 signature.** D4b says a write that cannot
  re-sign drops the signature, but nothing enforced it for the one case with no
  root change to trigger it: format 3 signs `audit_report_sha256`, so re-pointing a
  layer at different report bytes invalidated the signature while the Merkle root
  stayed put. Three things independently failed to notice — `stamp_merkle_metadata`
  drops a stale signature only when the ROOT changes; `resign_layers_format3`
  skipped a layer as "already format 3" by comparing the format NUMBER rather than
  whether the signature still verified; and `backfill_report_digest` documented "no
  re-stamp, no re-signature", true under format 2 and false since format 3.
  Measured: backfilling a digest onto one layer produced a layer claiming format 3
  whose signature failed verification, while a control layer passed.
  `stamp_report_reference` now drops the signature (and method/format) when the
  digest or ref actually changes, and only for format >= 3 — formats 1 and 2 do not
  cover the digest, so dropping there would de-attest a correctly signed layer.
  Idempotent calls keep the signature. A caller holding a key re-signs immediately;
  one without leaves an honestly unsigned layer instead of a signature that lies.

## [0.8.4] — 2026-08-20

### Added
- **Events query endpoint.** `GET /v1/ledger/layers/{layer_id}/events` returns
  the raw event log for a layer. Supports `finding_ref` and `source_type`
  filters, plus `limit`/`offset` pagination. Needed for SCI's two-person-rule
  read cutover (XWING-1322), console event timeline, and dashboard counts.

## [0.8.3] — 2026-08-20

### Changed
- contracts pin v0.5.4 -> v0.5.5 (widens `merkle_signature_format` enum to
  allow 3). Adds a CI guard: `SIGNATURE_FORMAT_CURRENT` must appear in the
  schema's enum, so bumping the constant without widening the schema fails.

## [0.8.2] — 2026-08-20

### Fixed
- **DbBackend keyed on path, not layer ID.** `load`/`store`/`mutate` used
  `str(path)` as the row key; `list_layer_ids()` returned those paths, which
  failed `LAYER_ID_PATTERN` validation on round-trip. Both backends now key on
  the stem. Conformance test pins the round-trip. Documents the opacity
  contract for `layer_id`.

## [0.8.1] — 2026-08-20

### Changed
- contracts pin v0.5.3 -> v0.5.4 (`layer_metadata.external_refs`, the
  CVE-provenance map). No behaviour change here; the bump keeps the
  single contracts version the whole workspace resolves to, since uv
  pins it by exact git tag and a split would fail resolution.

## [0.8.0] — 2026-08-20

**Three fixes found by pointing `materialize` at a real findings tree.** Measured
against `console__release-5.0/`: it reported **four layers, three of which were the
audit report, the triage report and a companion.**

### Fixed
- **`FileBackend.list_layer_ids` lists layers, not every `*.json`.** The
  discriminator is an `events` list — reports carry `findings` and no `events`.
  Shape rather than filename, because the service names files `<layer_id>.json`
  while a corpus tree names them `<repo>-findings-layer.json`. A first attempt also
  demanded `metadata.audit_report` and `needs_review`; that rejected the service's
  own layers, since `EMPTY_LAYER` is `{"events": []}`, and broke eight tests. An
  unparseable file is skipped for listing, not raised.
- **`upsert_layer` no longer erases a layer's projection when a run yields zero
  findings.** It deleted every row, so a layer that failed to parse or was skipped
  looked identical to one that had been emptied. Deleting a whole projection is now
  deliberate: `prune_empty=True` (CLI `--prune-empty`). A non-empty run still prunes
  stale refs, which is what keeps the projection honest after a re-baseline.
- **Database credentials off argv.** `--to postgresql://user:pass@host/db` put the
  password in `ps` for every local user. `LAAS_MATERIALIZE_URL` takes precedence,
  `--to` with an `@` warns, and the success line redacts.

## [0.7.1] — 2026-08-19

**Disposition merge, findings projection, and read-side API.**

### Added
- **`traust_ledger.disposition`** — deterministic merge engine over layer events
  (validity by evidence class, assurance, resolution tiers, conflict surfacing).
- **`traust_ledger.projection`** — `materialized_findings` schema for dashboard binding.
- **Findings API** — `GET /v1/ledger/layers/{id}/findings` (per-layer) and
  `GET /v1/ledger/findings` (paginated bulk with cursor and `since_epoch` filter).
- **Verify API** — `GET /v1/ledger/layers/{id}/verify` (Merkle integrity, optional
  signature check).
- **CLIs** — `python -m traust_ledger.cli.verify` (batch Merkle sweep) and
  `python -m traust_ledger.cli.materialize` (idempotent projection into SQLite/Postgres).
- **Deploy** — CronJob manifest for scheduled verification sweeps.
- **Report kinds** — REMEDIATION and VERIFICATION report ingestion (0.7.0 follow-on).

### Changed
- **Gates** — verified-identity checks use contracts 0.5.3 fields
  (`identity_verified`, `employee_status`) with `ldap_verified` fallback.
- **DbBackend** — layer listing for bulk findings and CLI iteration.
- Pin `traust-contracts` to `v0.5.3`.

### Tests
- Findings API, verify endpoint, materialize CLI, and expanded two-person-rule coverage.

## [0.7.0] — 2026-08-19

**Ledger-as-a-Service — FastAPI service, provider-agnostic identity model, and
TypedDict consolidation onto contracts Pydantic models.**

### Service

- **FastAPI service** (`traust_ledger.service`) — REST API for human disposition
  events (countersign, severity) and machine triage/validation report ingestion.
  Routes: `POST /v1/ledger/events`, `POST /v1/ledger/reports`,
  `GET /v1/ledger/layers/{id}`, `GET /healthz`.
- **Security gates**: machine-disposition rejection, human-identity requirement,
  two-person same-identity rule, rationale-length minimum, timestamp-bounds
  check, Merkle-epoch validation, verified-identity requirement for
  false-positive assertions.
- **Pluggable backends**: `FileBackend` (atomic tempfile + replace) and
  `DbBackend` (SQLite with `FOR UPDATE` locking). Backend conformance test
  suite ensures both satisfy the same contract.
- **Event builders**: `build_human_event` / `build_severity_event` construct
  validated `LayerEvent` instances via contracts Pydantic models, serialized to
  dicts at the writer boundary.
- **Report converters**: triage and validation report handlers with
  finding-ref resolution, auto-accept tier, risk-weight computation, and
  needs-review queue routing.
- **Layer finalization**: Merkle stamping + optional signing wired into the
  append transaction, so every write is atomic through finalization.
- Kubernetes deployment manifests (`deploy/`), Containerfile, `.env.example`.

### Identity model refactor

- **Provider-agnostic identity**: new fields `identity_verified`,
  `identity_provider`, `identity_issuer`, `identity_subject`,
  `employee_status` replace the LDAP-specific `ldap_verified` boolean.
  `ldap_verified` is retained read-only for backward compatibility with
  existing corpus events.
- **`ActorResolver`** composes an `IdentityVerifier` (OIDC or bearer) with an
  optional `EmployeeDirectory` (LDAP). Adapters: `OIDCVerifier` (JWT/JWKS),
  `BearerVerifier` (dev/test tokens), `LDAPDirectory` (bind + mail lookup).
- **Identity normalization**: human identity canonicalized to lowercased email
  at the adapter exit. OIDC uses the `email` claim (not `sub`), LDAP resolves
  `uid` → `mail`. Raw subject stored in `identity_subject` for audit.
- **Fallback readers**: `_is_actor_verified` / `_has_employee_status_active`
  check new fields first, fall back to `ldap_verified` for pre-refactor events.
  Shared helper in `traust-engine` (`_util.actor.is_actor_verified`).
- **Fail-closed config**: `auth_mode=oidc` requires `LAAS_OIDC_JWKS_URL` at
  startup; missing config raises `RuntimeError` instead of silently falling
  back to bearer.

### Contracts alignment

- **TypedDict consolidation**: removed 5 custom TypedDicts (`Actor`,
  `ActorResult`, `InteractiveSource`, `HumanEvent`, `SeverityEvent`) in favor
  of Pydantic models from `traust-contracts` (`LayerActor`, `LayerSource`,
  `LayerDisposition`, `LayerEvent`). Contracts repo is now the single source of
  truth for actor and event structure.
- Pin `traust-contracts` to `v0.5.2` (adds `identity_verified`,
  `identity_provider`, `identity_issuer`, `identity_subject`,
  `employee_status` to `LayerActor`).

### Tests

- 632 tests (was 487), covering service routes, auth enforcement, security
  gates, two-person rule, OIDC/bearer/LDAP adapters, report converters,
  backend conformance, deploy invariants, signing integrity, event builders,
  OpenAPI spec validation, and fixture replay.

## [0.6.0] — 2026-08-18

**Signature format 3 — the report digest is now inside the signature.**
Ledger plan §4.4.0a.

- `merkle_signature_payload` binds `audit_report_sha256`, and
  `SIGNATURE_FORMAT_CURRENT` is **3**. Format 2 left the digest *outside* the
  signature, so anyone able to write a layer could repoint it at a substituted
  report by rewriting the digest to match — provenance, but not tamper-evidence.
  A signature now covers events (via the Merkle root), claims (via the claim-hash
  digest) **and** the annotated report's bytes.
- An **absent** digest signs as `None`, a distinct value — so backfilling a digest
  later correctly invalidates the signature instead of passing silently.
- `merkle_signature_payload(meta, fmt=...)` is explicit, and verification
  reconstructs the payload for the format the layer records. **Format 2 verifies
  without complaint during the migration**: 8,906 layers carry it, and warning on
  each would drown the signal the warning exists to carry. Format 1 keeps its
  existing content-unbound warning.
- The signing test fixture pinned `merkle_signature_format = 2` as a literal and
  broke on the bump; it now tracks `SIGNATURE_FORMAT_CURRENT`, with a separate test
  covering the format-2 transition path explicitly.

**Every existing signature must be re-made** to gain the new binding. Until a layer
is re-signed it stays format 2 and remains valid — the corpus is not invalidated by
this release, only un-upgraded.

## [0.5.0] — 2026-08-18

**`traust_ledger.reports` — the layer's link to its baseline, content-addressed.**
Ledger plan §4.4.0 step 1.

- `report_sha256(path|bytes)` hashes the report's **exact bytes**, never a
  re-serialization: the corpus is mixed on `ensure_ascii`, so hashing a parsed dict
  would make the digest depend on which producer wrote the file. Pinned by test.
- `stamp_report_reference(layer, report, ref=...)` records
  `audit_report_sha256` (+ optional `audit_report_ref`); idempotent, so writers can
  call it unconditionally.
- `check_report_digest(layer, report)` returns a message or None. **Absent is not a
  failure** — 8,508 layers predate the field. **A mismatch is surfaced, never
  auto-healed**: it is the legitimate signal that the annotated bytes were rewritten
  (a re-audit, or a migration like the v1→v2 fingerprint re-stamp, which rewrote 361
  reports without touching a single claim), and silently re-recording it would erase
  the only evidence that happened.

Complements `claim_hashes` rather than duplicating it: claim hashes answer "did a
finding's claim change?", the digest answers "are these the bytes I annotated?".
Requires contracts >= 0.5.1, which declares both fields.

## [0.4.1] — 2026-08-18

- Adopt `traust-contracts>=0.5.0,<0.6`, which retires the shared
  golden-vector suite and `paths.vectors_dir()`. Nothing here read either after
  0.4.0 ported the cases in-repo, so this is a pin move only.
- `scripts/gen_identity_golden_vectors.py` → `scripts/gen_identity_recipe_vectors.py`,
  repointed from the deleted contracts vectors tree to
  `tests/fixtures/identity-recipe-vectors.json`. Its guard is the part worth
  keeping: it **refuses to rewrite hashes under an unchanged `ALGO_VERSION`**, so
  identity cannot be silently redefined by regenerating. It now also carries each
  case's `v1_expected_fingerprint` forward on every run, and takes `ALGO_VERSION`
  from `traust_ledger.identity` instead of a local copy that could drift.
- README: the "Golden vectors" section is now "Recipe regression fixtures", with
  the known limit restated — all 12 cases are ASCII, well-formed, and free of
  empty paths, so they passed green through every real divergence found in 2026-08.
  They are a regression net, not a correctness argument.

## [0.4.0] — 2026-08-18

**The recipe's regression net moves in-repo (plan D7, queue item 5).**

- `tests/fixtures/identity-recipe-vectors.json` — the 12 cases from
  `traust-contracts` `vectors/v1/finding-identity-golden-vectors.json`,
  ported here before that suite retires. D7 leaves no second-language port to hold
  to a shared oracle, but the recipe still must not change by accident, and these
  cover ground the divergence tests do not: scheme rewriting, `.git` stripping, the
  scp form, path dedup, the `lstrip` cutset quirk, CWE trimming.
- Every expected value was **recomputed under v2 and is identical to the retired
  suite's v1 value** — 12/12. `v1_expected_fingerprint` is retained per case, and a
  test asserts the equality, so a future v1→v2-style move shows up instead of being
  silently re-baselined. That equality is also why the suite could never have caught
  the divergences: every case is ASCII, well-formed, and free of empty paths.
- `no_locations_empty_pathset` is now pinned twice over: a legitimate lenient hash,
  and the exact shape `fingerprint(strict=True)` refuses — tying the fixtures to the
  open ~2,762-finding migration.
- `TestIdentityGoldenVectors` removed from `test_traust_ledger.py`: it read the suite
  from the installed contracts package, and leaving it pointing at a file scheduled
  for deletion would have broken on someone else's change rather than this one.

## [0.3.1] — 2026-08-18

- Depend on `traust-contracts>=0.4.5`, which declares the location-path rule
  and the `repo-scope-path` pseudo-path vocabulary that strict mode's error message
  points callers at. 0.3.0 shipped still pinned to 0.4.4, so a consumer adopting
  both hit uv's conflicting-URL refusal.

## [0.3.0] — 2026-08-18

**`fingerprint(strict=True)` refuses a finding with no usable location.**

- New `strict` keyword and `DegenerateIdentity` exception. Without it the recipe
  silently accepts input that cannot identify anything: measured 2026-08-18,
  **433 fingerprints were shared by 1,397 findings** whose only location was a
  repo-root marker, so "no SECURITY.md" and "not onboarded to OpenSSF Scorecard"
  in one repo were one identity — a disposition on either silently covered both.
- **No stamped value moves and `ALGO_VERSION` is untouched.** This narrows the
  recipe's *domain*, it does not change its *mapping*; every accepted input
  hashes exactly as before. That is also why a schema rule alone is not enough —
  a declared pattern only bites where validation runs, while nothing enters the
  ledger without an identity.
- The error names the escape hatch: an artifact path (an absent `SECURITY.md` is
  still `SECURITY.md`) or a controlled pseudo-path from
  `traust-contracts` `enums/v1/repo-scope-path.json`.
- **Default is `False` on purpose.** Flipping it before the corpus is migrated
  would refuse ~2,762 existing repo-root findings at stamp time. Backfill, then
  flip — the order P0.4 and P6 followed; the flip is a tracked plan item, and
  `test_default_is_lenient_until_the_corpus_is_migrated` is the test to invert
  when it lands.
- Adopts `traust-contracts>=0.4.5`, which declares the location-path rule
  and the pseudo-path vocabulary.

## [0.2.0] — 2026-08-18

**`algo_version` v2 — the fingerprint recipe changes (decision D8).**

- **A location path that canonicalizes to empty is dropped from the hashed set.**
  `.`, `/`, `./` and `/./` all reduce to `""`, and v1 tested the *raw* value for
  truthiness, so `['.', 'src/a.go']` hashed `";src/a.go"` — an empty component in
  the join. Measured on the corpus: 3,127 locations canonicalize to empty,
  **364 findings across 259 repos change value**, and the 2,762 repo-root-only
  findings hash identically either way (an all-empty set and a dropped-empty set
  are both `""`). Corpus re-stamp is deferred — it rewrites signed layers, so it
  waits on the signing key reaching the write path (plan P8).
- `identity.ALGO_VERSION` is new and is now the single source of the recipe
  version; `events.FINGERPRINT_ALGO_CURRENT` derives from it, so a bump cannot
  be recorded in one place and missed in the other.
- **ASCII-only case folding** (`ascii_lower` / `ascii_upper`, exported). Python's
  `str.lower()` applies full Unicode case mapping and Go's `strings.ToLower()`
  simple mapping, so `İ` (U+0130) yielded 2 codepoints in one language and 1 in
  the other. No corpus fingerprint moved: 0 of 8,270 reports carry a non-ASCII
  repository URL.
- **`primary_cwe` returns `CWE-0` for a blank value**, not `""`. The vector
  suite's own rules always said "'CWE-0' when absent/empty" and the Go SDK
  implemented it; this was a bug against the written contract. No corpus
  fingerprint moved: 0 reports carry a blank CWE.
- `tests/test_identity_recipe_v2.py` — regression fixtures for all three classes,
  taking over the role the retiring golden-vector suite played for the canonical
  implementation (D7). Every one of the 12 vectors passed green through all three
  divergences, which is why they could not have caught any of them.

## [0.1.7] — 2026-08-18

- **A changed Merkle root now drops the signature it invalidated.**
  `stamp_merkle_metadata` removes `merkle_root_signature` /
  `merkle_signing_method` / `merkle_signature_format` when the recomputed root
  differs from the stored one, and returns `True`; `stamp_and_sign` surfaces it
  as `SignAttempt.stale_signature_dropped` when it could not re-sign. A
  re-stamp producing the same root leaves a valid signature untouched.
  Previously the old signature survived beside the new root, so the layer read
  as signed-and-invalid — indistinguishable from tampering to a verifier, and
  strictly worse than the unsigned state that is normal before plan P8. Found
  on 9 layers of the Ex-Wing 5.0 embargo backfill (2026-08-17); the corpus
  passes in plan items B7 and P2's 417 layers would have reproduced it at scale.
- `SignAttempt.warning()` renders the one message a writer must print, covering
  both a failed signer and a dropped signature, so the six call sites stop
  hand-rolling the same conditional and cannot disagree about what is
  reportable.

## [0.1.6] — 2026-08-18

- `events.findings_from_events` — project event-carried claims (`eed94e9`).
  Entry added retrospectively; the release itself predates it.

## [0.1.5] — 2026-08-17

- Depend on `traust-contracts>=0.4.3,<0.5`. 0.4.3 declares
  `event.fingerprint` / `event.fingerprint_algo` — the stamps
  `events.attach_identity` has been writing all along, which `$defs.event`
  (`additionalProperties: false`) previously rejected. No change to the
  stamping code: the schema was wrong, not the writer.

## [0.1.4] — 2026-08-17

- Depend on `traust-contracts>=0.4.2,<0.5` (was `>=0.3,<0.4`). First link in
  the release train that lets consumers write `disposition.embargo`: the schema
  landed in contracts 0.4.0, but this constraint — and the `tag = "v0.3.0"`
  source pin below it — held every downstream at 0.3.x and made `uv lock` fail
  with conflicting URLs for one package.
- No kernel behaviour change; 277 tests pass unmodified against the new schemas.

## [0.1.1] — 2026-08-11

- Drop `contracts/` git submodule; depend on `traust-contracts>=0.2,<0.3` via pip/git tag
- Tests load golden vectors from installed `traust_contracts.paths.vectors_dir()`
- CI: `uv sync`, ruff, pytest, `uv build` (no `GIT_SUBMODULE_STRATEGY`)

## [0.1.0] — 2026-08-10

- Extracted from `traust` v0.260.1 (Task 3.3 of the contracts
  restructure): `identity` (frozen fingerprint primitives), `events`
  (claim-hash / event-id math), `integrity` (Merkle, stamping, signing —
  moved as-is), and the new `LedgerWriter` single write path (append-only,
  idempotent, atomic, `ldap_verified` enforcement, batch `append_events`).
- Golden vectors consumed from the `traust-contracts` submodule pin.
