# Service-layer identity

How traust-ledger authenticates callers (REST and CLI) and gates write operations.

## Design stance

**Every actor must be cryptographically verified.** There is no anonymous mode,
no "trust me" fallback, no static tokens. If you make security decisions about
code, you must prove who you are.

For solo developers: `ledger auth local --identity you@example.com` gets you
running in seconds with no external provider. For teams and production, use
`ledger auth login` with any OIDC provider (GitHub, Google, Keycloak, etc.).

This is intentional — the ledger records security decisions (false positives,
severity overrides, countersigns). Accountability is the product.

## Architecture

```
LedgerClient: LAAS_TOKEN env → LayerActor → handlers → LedgerWriter
CLI:           resolve_token() → LayerActor → handlers → LedgerWriter
REST:          extract_bearer(req) → IdentityPort.verify() → LayerActor → handlers → LedgerWriter
```

All three entry points resolve a `LayerActor` from an OIDC token then
delegate to shared handlers (`traust_ledger.handlers.*`). The difference is
where the token comes from:

- **LedgerClient**: `LAAS_TOKEN` env var (constructor requirement)
- **CLI**: env var (`LEDGER_TOKEN`), file (`LEDGER_TOKEN_PATH`), or cached credentials
- **REST**: `Authorization: Bearer <token>` header

## Identity port

Every protected endpoint goes through a single protocol:

```python
class IdentityPort(Protocol):
    def verify(self, request: Request) -> LayerActor: ...

    @classmethod
    def from_config(cls, config: ServiceConfig) -> Self: ...
```

Set `LAAS_IDENTITY_PROVIDER` to select the adapter. Implement the protocol
and `@register` to add your own.

## Endpoint protection

| Endpoint | Gate | Actor used for |
|---|---|---|
| `POST /v1/ledger/events` | `resolve_actor` — full verify, injects actor | Stamped on event source; enters Merkle leaf |
| `GET /v1/ledger/layers/{id}` | `require_identity` | Read gate |
| `GET /v1/ledger/layers/{id}/verify` | `require_identity` | Read gate |
| `GET /v1/ledger/layers/{id}/findings` | `require_identity` | Read gate |
| `GET /v1/ledger/layers/{id}/events` | `require_identity` | Read gate |
| `GET /v1/ledger/findings` | `require_identity` | Read gate |
| `GET /healthz` | None | Public |

Both `resolve_actor` and `require_identity` call
`ActorResolver.resolve(request)` which runs the adapter verification chain.
Invalid credentials → 401 before the handler executes.

## Built-in providers

| Provider | `LAAS_IDENTITY_PROVIDER=` | What it does | Principal types |
|---|---|---|---|
| OIDC | `oidc` (default) | Validates JWT against JWKS endpoint | Human (identity claim) or machine (`sub`/`azp` fallback) |
| Local | _(auto-detected)_ | Self-signed JWT from local keypair | Human only |

Local is not a service-layer provider — it is a CLI/client convenience. When
no OIDC config is present and a local keypair exists (`~/.config/traust-ledger/`),
the verifier auto-detects the local JWKS and validates the token. Actors are
stamped `identity_provider=local`.

## Provider configuration

### OIDC

| Variable | Required | What it does |
|---|---|---|
| `LAAS_OIDC_JWKS_URL` | Yes | JWKS endpoint for signature verification |
| `LAAS_OIDC_ISSUER` | No | Expected `iss` claim (rejects mismatches when set) |
| `LAAS_OIDC_AUDIENCE` | No | Expected `aud` claim |
| `LAAS_OIDC_IDENTITY_CLAIM` | No | Claim for human identity (default: `email`) |
| `LAAS_OIDC_MACHINE_CLAIM` | No | Claim whose absence signals machine (default: `azp`) |

Fails closed: missing `LAAS_OIDC_JWKS_URL` with `identity_provider=oidc` is a
startup error.

Machine callers (CI pipelines, services) authenticate via OIDC client-credentials
grant or Kubernetes projected service-account tokens — both produce standard JWTs
that the OIDC adapter verifies identically to human tokens.

## Local development and testing

### Quick start: local identity (no external provider)

For solo evaluation or local development — no OIDC provider needed:

```bash
ledger auth local --identity you@example.com
```

This generates a local EC keypair, mints a JWT, and caches it. All CLI
commands work immediately. The identity is remembered for subsequent runs
(just `ledger auth local` to refresh).

For scripts and CI, set an env var instead:

```bash
export LEDGER_LOCAL_IDENTITY=you@example.com
ledger submit ...   # token auto-minted on first use
```

Local actors are stamped with `identity_provider=local` and
`identity_verified=true`. All domain gates pass. When you move to
production, switch to `ledger auth login` (OIDC) — the upgrade changes
only `identity_provider`; existing ledger events retain their provenance.

**Note:** See [`auth.md`](auth.md) for how token resolution and verifier
selection interact, including the env var precedence chain.

### OIDC setup (GitHub, Google, Keycloak, etc.)

For production or team environments, use a real OIDC provider:

```bash
ledger config set --issuer https://accounts.google.com --client-id <your-client-id>
ledger auth login
```

Or with GitHub:

```bash
ledger config set --issuer https://token.actions.githubusercontent.com --client-id <your-client-id>
ledger auth login
```

### Local dev REST

Use the mock OIDC server for local REST API development:

```bash
make mock-idp        # starts mockserver/mockserver on :1080
export LAAS_OIDC_JWKS_URL=http://localhost:1080/.well-known/jwks.json
```

This gives you a real OIDC flow locally — tokens are issuable and verifiable.
Stop it with `make mock-idp-stop`.

Or run full coverage (starts/stops the mock IdP automatically):

```bash
make coverage-all
```

## Principal types

Adapters stamp `kind` on the `LayerActor`:

- **human** — identified by a personal claim (email, UPN, etc.)
- **machine** — service account, API key, workload identity

The `kind` decision lives inside the adapter. `ActorResolver` trusts whatever
the adapter stamps. The OIDC adapter uses configurable claim mapping; the API
key adapter always stamps machine.

## Employee-directory cross-check (optional)

Identity verification answers *who is this token for*. A deployment may add a
narrower question the ledger cannot answer itself — *is that person still a
current member of the organisation* — by supplying an **employee directory
command**. It applies after verification on every write path, REST and the
in-process `LedgerClient` alike (`traust_ledger.auth.directory`):

```bash
export LEDGER_DIRECTORY_COMMAND="python3 /opt/extension/bin/validate_employee.py"
export LEDGER_DIRECTORY_TIMEOUT=60   # seconds, optional
```

The command is run as `<command> <identity>` and must print one line
`RESULT uid=<identity> status=<active|contingent|terminated|not_found|…>`.
Only `active` passes; the actor is stamped `employee_status: active`. Any
other status refuses the actor (`InvalidAuthError` on REST, `LedgerError` in
the SDK). A command that cannot run, exits non-zero, times out, or prints no
RESULT line is `unavailable` — also a refusal. A command that is configured
but whose program does not exist fails at startup, not at the first write.
Machine actors are never cross-checked.

Unset means no cross-check: the token stands alone. That is the default and
what an adopter without a corporate directory gets. The ledger ships no
directory implementation; the v0.16 in-tree LDAP adapter is not coming back —
directories are deployment extensions.

## Programmatic override

`create_app(config, verifier=my_adapter)` bypasses the registry. Use for tests
or custom adapters that aren't registered.

## Adding a new provider

1. Create `traust_ledger/service/identity/myprovider.py`
2. Implement `IdentityPort` — `verify(request)` and `from_config(config)`
3. Decorate with `@register("myprovider")`
4. Add any config fields to `ServiceConfig`
5. Set `LAAS_IDENTITY_PROVIDER=myprovider`

## Historical note: quarantine / needs_review

The `needs_review` queue on layers exists for content-quality gates (ambiguous
statements, weak confirmations, severity proposals, etc.). These are queued by
the harness validation pipeline, not by traust-ledger's event handler.

Previously (pre-v0.16), the event handler quarantined submissions with
unverified actor identity. With OIDC mandatory on all write paths, that
condition is unreachable — the caller is either cryptographically verified or
rejected at the door. The identity quarantine feeder was removed; the
`resolve` command remains for draining any existing queued items and for
harness-queued content-quality items.
