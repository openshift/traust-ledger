from __future__ import annotations

from dataclasses import replace

from traust_ledger._internal.integrity import sign_if_configured, stamp_merkle_metadata
from traust_ledger._internal.integrity.signing import SigningConfig
from traust_ledger.config import ServiceConfig
from traust_ledger.constants import (
    LAYER_KEY_METADATA,
    METADATA_KEY_MERKLE_ROOT,
)
from traust_ledger.service.errors import SigningFailedError, SigningRequiredError


def require_signing_configured(config: ServiceConfig) -> None:
    if not config.signing_required:
        return
    if config.signing_key_path:
        return
    if config.signing_method in ("sigstore-oidc", "identity"):
        return
    raise SigningRequiredError()


def _signing_config(config: ServiceConfig) -> SigningConfig:
    method_aliases = {
        "cosign": "keypair",
        "sigstore-oidc": "identity",
    }
    method = method_aliases.get(config.signing_method, config.signing_method)
    harness = SigningConfig.from_env()
    return SigningConfig(
        method=method,
        key_path=config.signing_key_path or harness.key_path,
        oidc_issuer=config.oidc_issuer_url or harness.oidc_issuer,
        oidc_client_id=config.oidc_client_id or harness.oidc_client_id,
        oidc_token=harness.oidc_token,
        expected_identity=harness.expected_identity,
        allow_interactive=harness.allow_interactive,
        ca_url=harness.ca_url,
        tlog_url=harness.tlog_url,
    )


def finalize_layer(
    layer: dict[str, object],
    config: ServiceConfig,
    *,
    layer_id: str = "unknown",
) -> str:
    dropped = stamp_merkle_metadata(layer)
    attempt = sign_if_configured(layer, _signing_config(config))
    if dropped and attempt.status != "signed":
        attempt = replace(attempt, stale_signature_dropped=True)
    if config.signing_required and attempt.status != "signed":
        raise SigningFailedError(layer_id=layer_id)
    metadata = layer.get(LAYER_KEY_METADATA)
    if not isinstance(metadata, dict):
        return ""
    root = metadata.get(METADATA_KEY_MERKLE_ROOT)
    return str(root) if root else ""
