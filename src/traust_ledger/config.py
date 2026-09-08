from __future__ import annotations

from pydantic import BaseModel


class ServiceConfig(BaseModel):
    """Plain config bag — importable with no optional deps.

    For env-auto-loading (REST service), use ``ServiceSettings`` from
    ``traust_ledger.service.settings`` which inherits this and adds
    ``pydantic_settings.BaseSettings``.
    """

    backend_type: str = "file"
    database_url: str | None = None
    data_dir: str = "/var/lib/laas/data"
    signing_required: bool = False
    signing_key_path: str | None = None
    signing_method: str = "cosign"
    log_level: str = "INFO"

    # ── Service-layer identity (who is calling the API) ──
    identity_provider: str = "oidc"

    # OIDC token validation (guards API access)
    oidc_issuer: str | None = None
    oidc_audience: str | None = None
    oidc_jwks_url: str | None = None
    oidc_machine_claim: str = "azp"
    oidc_identity_claim: str = "email"

    # Multiple trusted OIDC issuers — JSON array of objects.
    oidc_trust: str = ""

    # ── Ledger signing (sigstore-oidc, separate from API auth) ──
    oidc_issuer_url: str | None = None
    oidc_client_id: str | None = None
