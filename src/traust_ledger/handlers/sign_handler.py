"""Sign handler — the single sign path for CLI, REST, and LedgerClient.

All three entry points converge here. Callers load + write the layer
themselves (via backend); this function owns stamp + sign only.
"""

from __future__ import annotations

from traust_ledger._internal.integrity.ledger import sign_if_configured, stamp_merkle_metadata
from traust_ledger._internal.integrity.signing import SigningConfig
from traust_ledger.config import ServiceConfig
from traust_ledger.errors import SigningFailedError


def _credentials_from_config(config: ServiceConfig) -> SigningConfig:
    return SigningConfig(
        method=config.signing_method,
        key_path=config.signing_key_path,
        oidc_issuer=getattr(config, "oidc_issuer_url", None),
        oidc_client_id=getattr(config, "oidc_client_id", None),
    )


def sign_layer(
    layer: dict,
    config: ServiceConfig,
    *,
    rekor: bool = False,
    credentials: SigningConfig | None = None,
) -> dict:
    """Stamp Merkle metadata and sign a layer dict in-place.

    Args:
        credentials: Explicit signing credentials. When ``None``,
            derived from ``config`` fields (REST / LedgerClient path).
            The CLI passes its own ``SigningConfig`` built from args.
    """
    resolved = credentials or _credentials_from_config(config)

    stamp_merkle_metadata(layer)
    attempt = sign_if_configured(layer, config=resolved, rekor=rekor)

    if attempt.status == "failed":
        raise SigningFailedError(layer_id="(via sign_handler)")

    return {"status": attempt.status, "method": attempt.method}
