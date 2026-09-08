"""Lazy `httpx2` access for the OIDC network paths.

`httpx2` ships in the optional **`cli`** extra, but `traust_ledger.auth` sits on
the import path of every *write*: `LedgerClient` → `resolve_auth` →
`auth.config` → `auth.discovery`. Importing it at module scope therefore made
an HTTP client mandatory for callers that never make an HTTP request — a
locally-minted token (`ledger auth local`) is verified against a file-based
JWKS and touches no network at all.

The effect on a plain `traust-ledger` install (no extra) was that appending an
event died before it began:

    ModuleNotFoundError: No module named 'httpx2'

which took out every SDK writer, `traust-engine`'s `LedgerService`, and all
25 of the harness call sites that go through it.

So the import happens inside the functions that genuinely talk to an OIDC
provider. Annotations are unaffected: these modules carry
`from __future__ import annotations`, so `httpx.Response` in a signature is a
string and is never evaluated. Runtime references — `httpx.Client`, and the
`except httpx.TimeoutException` clauses in the device-code flow — are covered
because they execute inside a function that has already called `http()`.
"""

from __future__ import annotations

from types import ModuleType


def http() -> ModuleType:
    """Return the `httpx2` module, or raise with the fix rather than the symptom."""
    try:
        import httpx2
    except ModuleNotFoundError as exc:  # pragma: no cover - install-dependent
        raise RuntimeError(
            "This OIDC call needs an HTTP client, which ships in the optional "
            "'cli' extra: install `traust-ledger[cli]`. Local identity "
            "(`ledger auth local`) requires no HTTP client and no extra."
        ) from exc
    return httpx2
