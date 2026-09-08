"""P1 signing integrity: finalize_layer must stamp and sign like stamp_and_sign."""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

from traust_ledger._internal.integrity import SignAttempt, stamp_merkle_metadata
from traust_ledger._internal.integrity.signing import SigningConfig, SignResult
from traust_ledger._internal.layer_finalize import _signing_config, finalize_layer
from traust_ledger.config import ServiceConfig
from traust_ledger.service.errors import SigningFailedError

SIG = "dGVzdC1zaWduYXR1cmU="


def _layer(n: int = 1) -> dict:
    return {
        "metadata": {},
        "events": [
            {
                "event_id": f"e{i}",
                "finding_ref": f"F-{i}",
                "recorded_at": "2026-01-01T00:00:00Z",
                "source": {},
                "disposition": {},
                "rationale": "r",
            }
            for i in range(n)
        ],
    }


def _signed_layer(n: int = 1) -> dict:
    layer = _layer(n)
    stamp_merkle_metadata(layer)
    layer["metadata"]["merkle_root_signature"] = "MEUCIQD-fake-signature"
    layer["metadata"]["merkle_signing_method"] = "keypair"
    layer["metadata"]["merkle_signature_format"] = "sigstore-bundle"
    return layer


def _mock_keypair_backend() -> MagicMock:
    backend = MagicMock()
    backend.method_name = "keypair"
    backend.sign.return_value = SignResult(signature=SIG, success=True)
    return backend


@patch("traust_ledger._internal.integrity.ledger.get_backend_from_config")
def test_optional_signing_still_signs_when_key_configured(
    mock_get_backend: MagicMock,
) -> None:
    """P1-5: signing_required=false must not skip signing when a key is set."""
    mock_get_backend.return_value = _mock_keypair_backend()
    layer = _layer()
    config = ServiceConfig(
        signing_required=False,
        signing_key_path="/tmp/test-key.pem",
        signing_method="cosign",
    )

    finalize_layer(layer, config)

    mock_get_backend.assert_called_once()
    assert layer["metadata"]["merkle_root_signature"] == SIG


@patch("traust_ledger._internal.integrity.ledger.get_backend_from_config")
def test_append_to_signed_layer_re_signs_when_optional_signing_configured(
    mock_get_backend: MagicMock,
) -> None:
    """P1-5: appending drops the stale sig; finalize must re-sign, not leave unsigned."""
    mock_get_backend.return_value = _mock_keypair_backend()
    layer = _signed_layer()
    layer["events"].append(
        {
            "event_id": "e-new",
            "finding_ref": "F-new",
            "recorded_at": "2026-08-17T00:00:00Z",
            "source": {},
            "disposition": {},
            "rationale": "r",
        }
    )
    config = ServiceConfig(
        signing_required=False,
        signing_key_path="/tmp/test-key.pem",
        signing_method="cosign",
    )

    finalize_layer(layer, config)

    assert layer["metadata"]["merkle_root_signature"] == SIG
    assert layer["metadata"]["merkle_signing_method"] == "keypair"


@patch("traust_ledger._internal.layer_finalize.sign_if_configured")
def test_optional_signing_does_not_fail_when_signing_fails(
    mock_sign: MagicMock,
) -> None:
    """P1-5: signing_required=false tolerates a configured-but-broken signer."""
    mock_sign.return_value = SignAttempt("failed", method="keypair", error="boom")
    layer = _layer()
    config = ServiceConfig(
        signing_required=False,
        signing_key_path="/tmp/test-key.pem",
    )

    root = finalize_layer(layer, config)

    assert root
    mock_sign.assert_called_once()


def test_required_signing_fails_when_signing_fails() -> None:
    """P1-5: signing_required=true must hard-fail when signing does not succeed."""
    layer = _layer()
    config = ServiceConfig(
        signing_required=True,
        signing_key_path="/nonexistent/key.pem",
    )

    with pytest.raises(SigningFailedError):
        finalize_layer(layer, config)


@patch.dict(os.environ, {"LAAS_SIGNING_OIDC_TOKEN": "ci-oidc-token"})
def test_signing_config_passes_oidc_token_for_identity_mode() -> None:
    """P1-6: identity signing needs oidc_token wired from the LAAS env."""
    config = ServiceConfig(
        signing_method="sigstore-oidc",
        oidc_issuer_url="https://accounts.example.com",
        oidc_client_id="laas-client",
    )

    signing = _signing_config(config)

    assert signing.method == "identity"
    assert signing.oidc_token == "ci-oidc-token"
    assert signing.oidc_issuer == "https://accounts.example.com"
    assert signing.oidc_client_id == "laas-client"


@patch("traust_ledger._internal.integrity.ledger.get_backend_from_config")
@patch.dict(os.environ, {"LAAS_SIGNING_OIDC_TOKEN": "ci-oidc-token"})
def test_identity_signing_succeeds_when_token_configured(
    mock_get_backend: MagicMock,
) -> None:
    """P1-6: signing_required + identity mode must not always return unconfigured."""
    backend = MagicMock()
    backend.method_name = "identity"
    backend.sign.return_value = SignResult(signature='{"bundle":true}', success=True)
    mock_get_backend.return_value = backend

    layer = _layer()
    config = ServiceConfig(
        signing_required=True,
        signing_method="sigstore-oidc",
        oidc_issuer_url="https://accounts.example.com",
        oidc_client_id="laas-client",
    )

    finalize_layer(layer, config)

    mock_get_backend.assert_called_once()
    passed_config = mock_get_backend.call_args.args[0]
    assert isinstance(passed_config, SigningConfig)
    assert passed_config.oidc_token == "ci-oidc-token"
    assert layer["metadata"]["merkle_root_signature"] == '{"bundle":true}'
