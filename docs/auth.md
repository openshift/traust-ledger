# Authentication

How traust-ledger obtains a token, verifies it, and derives an actor.

## Quick start

```bash
ledger auth local --identity you@example.com   # no OIDC needed
ledger auth local --machine --identity triage/0.32.0  # automation
```

## How it works

`resolve_auth()` resolves a credential and builds its matching verifier
in one step — they cannot disagree.

```
resolve_auth()
  ├─ resolve credential (one winner, env first)
  │    1. LAAS_TOKEN            env
  │    2. LEDGER_TOKEN_PATH     env (file — errors if unreadable)
  │    3. LEDGER_TOKEN          env
  │    4. stored credential     ~/.config/traust-ledger/
  │    5. auto-mint             LEDGER_LOCAL_IDENTITY
  │
  ├─ build matching verifier (one winner)
  │    credential source → OIDC keys or local keys, never both
  │
  └─ ResolvedCredential(token, verifier, source)
         │
         verifier.verify(token) → LayerActor
```

The REST service does not use `resolve_auth()` — it receives explicit
config at startup via [`IdentityPort`](service-identity.md).

## Verifier strategies

| Strategy | Keys | Issuer |
|----------|------|--------|
| OIDC | `LEDGER_OIDC_JWKS_URL` or discovery from `LEDGER_OIDC_ISSUER` | Configured issuer |
| Local | `~/.config/traust-ledger/local-jwks.json` | `local` |

## Actor derivation

| Claims | Kind |
|--------|------|
| `azp` present, `email` absent | machine |
| `email` present | human |
| `sub` only | machine |

## Environment variables

The optional employee-directory cross-check (`LEDGER_DIRECTORY_COMMAND`,
`LEDGER_DIRECTORY_TIMEOUT`) is documented in
[service-identity.md](service-identity.md#employee-directory-cross-check-optional);
it applies to the SDK and CLI paths as well as REST.

| Variable | Purpose |
|----------|---------|
| `LAAS_TOKEN` | Token override (wins everything) |
| `LEDGER_TOKEN_PATH` | Token file |
| `LEDGER_TOKEN` | Token value |
| `LEDGER_LOCAL_IDENTITY` | Auto-mint identity |
| `LEDGER_LOCAL_MACHINE` | Force machine kind on auto-mint |
| `LEDGER_OIDC_JWKS_URL` | JWKS endpoint |
| `LEDGER_OIDC_ISSUER` | Issuer (triggers discovery if no JWKS URL) |
| `LEDGER_OIDC_AUDIENCE` | Expected `aud` claim |

The REST service reads `LAAS_OIDC_*` equivalents via `pydantic-settings`.

## Related docs

| Doc | Scope |
|-----|-------|
| [service-identity.md](service-identity.md) | REST API auth, provider config, endpoint protection |
| [ledger-integrity.md](ledger-integrity.md) | Merkle tree, signing, write gates |
