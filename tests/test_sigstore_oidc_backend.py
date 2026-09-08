#!/usr/bin/env python3
"""Tests for traust_ledger._internal.integrity.signing.SigstoreOIDCBackend and
LAAS_SIGNING_* env var configuration."""

from __future__ import annotations

import json
import os
import sys
import unittest
from unittest import mock

from traust_ledger._internal.integrity.signing import (
    SigningConfig,
    SigstoreOIDCBackend,
    get_backend_from_config,
)

FAKE_BUNDLE_JSON = json.dumps(
    {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {"certificate": {"rawBytes": "AAAA"}},
        "messageSignature": {"messageDigest": {"algorithm": "SHA2_256", "digest": "AAAA"}},
    }
)


class TestSigningConfigFromEnv(unittest.TestCase):
    @mock.patch.dict(
        os.environ,
        {
            "LAAS_SIGNING_METHOD": "identity",
            "LAAS_SIGNING_KEY_PATH": "/tmp/key.pem",
            "LAAS_SIGNING_OIDC_ISSUER": "https://accounts.google.com",
            "LAAS_SIGNING_OIDC_CLIENT_ID": "my-client",
            "LAAS_SIGNING_EXPECTED_IDENTITY": "user@example.com",
            "LAAS_SIGNING_OIDC_TOKEN": "/tmp/token",
            "LAAS_SIGNING_OIDC_INTERACTIVE": "0",
            "LAAS_SIGNING_CA_URL": "https://ca.example.com",
            "LAAS_SIGNING_TLOG_URL": "https://tlog.example.com",
        },
    )
    def test_from_env_loads_all_fields(self):
        config = SigningConfig.from_env()
        self.assertEqual(config.method, "identity")
        self.assertEqual(config.key_path, "/tmp/key.pem")
        self.assertEqual(config.oidc_issuer, "https://accounts.google.com")
        self.assertEqual(config.oidc_client_id, "my-client")
        self.assertEqual(config.expected_identity, "user@example.com")
        self.assertEqual(config.oidc_token, "/tmp/token")
        self.assertFalse(config.allow_interactive)
        self.assertEqual(config.ca_url, "https://ca.example.com")
        self.assertEqual(config.tlog_url, "https://tlog.example.com")

    @mock.patch.dict(os.environ, {}, clear=True)
    def test_from_env_defaults(self):
        config = SigningConfig.from_env()
        self.assertEqual(config.method, "keypair")
        self.assertIsNone(config.key_path)
        self.assertIsNone(config.oidc_issuer)
        self.assertIsNone(config.oidc_client_id)
        self.assertIsNone(config.expected_identity)
        self.assertIsNone(config.oidc_token)
        self.assertFalse(config.allow_interactive)
        self.assertIsNone(config.ca_url)
        self.assertIsNone(config.tlog_url)

    @mock.patch.dict(os.environ, {"LAAS_SIGNING_OIDC_INTERACTIVE": "1"})
    def test_interactive_enabled_explicitly(self):
        config = SigningConfig.from_env()
        self.assertTrue(config.allow_interactive)

    @mock.patch.dict(os.environ, {"LAAS_SIGNING_OIDC_INTERACTIVE": "0"})
    def test_interactive_disabled(self):
        config = SigningConfig.from_env()
        self.assertFalse(config.allow_interactive)

    @mock.patch.dict(os.environ, {"LAAS_SIGNING_METHOD": "identity"}, clear=True)
    def test_from_env_reads_laas_vars(self):
        config = SigningConfig.from_env()
        self.assertEqual(config.method, "identity")


class TestGetBackendFromConfig(unittest.TestCase):
    def test_oidc_backend_receives_all_params(self):
        config = SigningConfig(
            method="identity",
            oidc_issuer="https://issuer.example.com",
            oidc_client_id="client-123",
            expected_identity="ci@example.com",
            oidc_token="my-token",
            allow_interactive=False,
            ca_url="https://ca.example.com",
            tlog_url="https://tlog.example.com",
        )
        backend = get_backend_from_config(config)
        self.assertIsInstance(backend, SigstoreOIDCBackend)
        self.assertEqual(backend._oidc_issuer, "https://issuer.example.com")
        self.assertEqual(backend._oidc_client_id, "client-123")
        self.assertEqual(backend._expected_identity, "ci@example.com")
        self.assertEqual(backend._oidc_token, "my-token")
        self.assertFalse(backend._allow_interactive)
        self.assertEqual(backend._ca_url, "https://ca.example.com")
        self.assertEqual(backend._tlog_url, "https://tlog.example.com")

    def test_key_based_backend(self):
        config = SigningConfig(method="keypair")
        backend = get_backend_from_config(config)
        from traust_ledger._internal.integrity.signing import CosignBackend

        self.assertIsInstance(backend, CosignBackend)

    def test_invalid_method_raises(self):
        config = SigningConfig(method="unknown")
        with self.assertRaises(ValueError):
            get_backend_from_config(config)


class TestSigstoreOIDCBackendAvailable(unittest.TestCase):
    def test_available_without_sigstore(self):
        backend = SigstoreOIDCBackend()
        with mock.patch.dict(sys.modules, {"sigstore": None}):
            pass
        result = backend.available()
        self.assertIsInstance(result, bool)

    def test_method_name(self):
        backend = SigstoreOIDCBackend()
        self.assertEqual(backend.method_name, "identity")


class TestSigstoreOIDCBackendSign(unittest.TestCase):
    @mock.patch.dict(
        sys.modules,
        {"sigstore": None, "sigstore.sign": None, "sigstore.models": None, "sigstore.oidc": None},
    )
    def test_sign_without_sigstore_installed(self):
        backend = SigstoreOIDCBackend()
        result = backend.sign(b"payload", "")
        self.assertFalse(result.success)
        self.assertIn("sigstore package not installed", result.error)

    def test_sign_no_token_available(self):
        mock_sigstore_oidc = mock.MagicMock()
        mock_sigstore_oidc.detect_credential.return_value = None

        with mock.patch.dict(
            sys.modules,
            {
                "sigstore": mock.MagicMock(),
                "sigstore.sign": mock.MagicMock(),
                "sigstore.models": mock.MagicMock(),
                "sigstore.oidc": mock_sigstore_oidc,
            },
        ):
            backend = SigstoreOIDCBackend(oidc_token=None)
            result = backend.sign(b"payload", "")
        self.assertFalse(result.success)
        self.assertIn("No OIDC token available", result.error)

    def test_sign_with_explicit_token(self):
        mock_bundle = mock.MagicMock()
        mock_bundle.to_json.return_value = FAKE_BUNDLE_JSON

        mock_signer = mock.MagicMock()
        mock_signer.sign_artifact.return_value = mock_bundle
        mock_signer.__enter__ = mock.Mock(return_value=mock_signer)
        mock_signer.__exit__ = mock.Mock(return_value=False)

        mock_signing_context = mock.MagicMock()
        mock_signing_context.signer.return_value = mock_signer

        mock_trust_config = mock.MagicMock()
        mock_client_trust_config = mock.MagicMock()
        mock_client_trust_config.production.return_value = mock_trust_config

        mock_sigstore_sign = mock.MagicMock()
        mock_sigstore_sign.SigningContext.from_trust_config.return_value = mock_signing_context

        mock_sigstore_models = mock.MagicMock()
        mock_sigstore_models.ClientTrustConfig = mock_client_trust_config

        mock_sigstore_oidc = mock.MagicMock()
        mock_sigstore_oidc.IdentityToken.return_value = mock.MagicMock()

        with mock.patch.dict(
            sys.modules,
            {
                "sigstore": mock.MagicMock(),
                "sigstore.sign": mock_sigstore_sign,
                "sigstore.models": mock_sigstore_models,
                "sigstore.oidc": mock_sigstore_oidc,
            },
        ):
            backend = SigstoreOIDCBackend(oidc_token="explicit-token-value")
            result = backend.sign(b"test-payload", "")

        self.assertTrue(result.success)
        self.assertEqual(result.signature, FAKE_BUNDLE_JSON)
        mock_sigstore_oidc.detect_credential.assert_not_called()
        mock_sigstore_oidc.IdentityToken.assert_called_once_with(
            "explicit-token-value", client_id="sigstore"
        )

    def test_sign_with_ambient_credential(self):
        mock_bundle = mock.MagicMock()
        mock_bundle.to_json.return_value = FAKE_BUNDLE_JSON

        mock_signer = mock.MagicMock()
        mock_signer.sign_artifact.return_value = mock_bundle
        mock_signer.__enter__ = mock.Mock(return_value=mock_signer)
        mock_signer.__exit__ = mock.Mock(return_value=False)

        mock_signing_context = mock.MagicMock()
        mock_signing_context.signer.return_value = mock_signer

        mock_trust_config = mock.MagicMock()
        mock_client_trust_config = mock.MagicMock()
        mock_client_trust_config.production.return_value = mock_trust_config

        mock_sigstore_sign = mock.MagicMock()
        mock_sigstore_sign.SigningContext.from_trust_config.return_value = mock_signing_context

        mock_sigstore_models = mock.MagicMock()
        mock_sigstore_models.ClientTrustConfig = mock_client_trust_config

        mock_sigstore_oidc = mock.MagicMock()
        mock_sigstore_oidc.detect_credential.return_value = "ambient-token"
        mock_sigstore_oidc.IdentityToken.return_value = mock.MagicMock()

        with mock.patch.dict(
            sys.modules,
            {
                "sigstore": mock.MagicMock(),
                "sigstore.sign": mock_sigstore_sign,
                "sigstore.models": mock_sigstore_models,
                "sigstore.oidc": mock_sigstore_oidc,
            },
        ):
            backend = SigstoreOIDCBackend(oidc_token=None)
            result = backend.sign(b"test-payload", "")

        self.assertTrue(result.success)
        mock_sigstore_oidc.detect_credential.assert_called_once()
        mock_sigstore_oidc.IdentityToken.assert_called_once_with(
            "ambient-token", client_id="sigstore"
        )

    def test_sign_malformed_ambient_falls_through_to_interactive(self):
        """Malformed ambient credential falls through to interactive OAuth2."""
        mock_identity_token = mock.MagicMock()

        mock_bundle = mock.MagicMock()
        mock_bundle.to_json.return_value = FAKE_BUNDLE_JSON

        mock_signer = mock.MagicMock()
        mock_signer.sign_artifact.return_value = mock_bundle
        mock_signer.__enter__ = mock.Mock(return_value=mock_signer)
        mock_signer.__exit__ = mock.Mock(return_value=False)

        mock_signing_context = mock.MagicMock()
        mock_signing_context.signer.return_value = mock_signer

        mock_trust_config = mock.MagicMock()
        mock_client_trust_config = mock.MagicMock()
        mock_client_trust_config.production.return_value = mock_trust_config

        mock_sigstore_sign = mock.MagicMock()
        mock_sigstore_sign.SigningContext.from_trust_config.return_value = mock_signing_context

        mock_sigstore_models = mock.MagicMock()
        mock_sigstore_models.ClientTrustConfig = mock_client_trust_config

        mock_issuer = mock.MagicMock()
        mock_issuer.identity_token.return_value = mock_identity_token

        mock_sigstore_oidc = mock.MagicMock()
        mock_sigstore_oidc.detect_credential.return_value = "not-a-valid-jwt"
        mock_sigstore_oidc.IdentityToken.side_effect = ValueError("invalid JWT")
        mock_sigstore_oidc.Issuer.production.return_value = mock_issuer

        with mock.patch.dict(
            sys.modules,
            {
                "sigstore": mock.MagicMock(),
                "sigstore.sign": mock_sigstore_sign,
                "sigstore.models": mock_sigstore_models,
                "sigstore.oidc": mock_sigstore_oidc,
            },
        ):
            backend = SigstoreOIDCBackend(
                oidc_token=None,
                allow_interactive=True,
            )
            result = backend.sign(b"test-payload", "")

        self.assertTrue(result.success)
        mock_sigstore_oidc.detect_credential.assert_called_once()
        mock_sigstore_oidc.IdentityToken.assert_called_once_with(
            "not-a-valid-jwt", client_id="sigstore"
        )
        mock_issuer.identity_token.assert_called_once_with()

    def test_sign_interactive_flow(self):
        """When no explicit/ambient token, falls back to Issuer interactive flow."""
        mock_identity_token = mock.MagicMock()

        mock_bundle = mock.MagicMock()
        mock_bundle.to_json.return_value = FAKE_BUNDLE_JSON

        mock_signer = mock.MagicMock()
        mock_signer.sign_artifact.return_value = mock_bundle
        mock_signer.__enter__ = mock.Mock(return_value=mock_signer)
        mock_signer.__exit__ = mock.Mock(return_value=False)

        mock_signing_context = mock.MagicMock()
        mock_signing_context.signer.return_value = mock_signer

        mock_trust_config = mock.MagicMock()
        mock_client_trust_config = mock.MagicMock()
        mock_client_trust_config.production.return_value = mock_trust_config

        mock_sigstore_sign = mock.MagicMock()
        mock_sigstore_sign.SigningContext.from_trust_config.return_value = mock_signing_context

        mock_sigstore_models = mock.MagicMock()
        mock_sigstore_models.ClientTrustConfig = mock_client_trust_config

        mock_issuer = mock.MagicMock()
        mock_issuer.identity_token.return_value = mock_identity_token

        mock_sigstore_oidc = mock.MagicMock()
        mock_sigstore_oidc.detect_credential.return_value = None
        mock_sigstore_oidc.Issuer.production.return_value = mock_issuer

        with mock.patch.dict(
            sys.modules,
            {
                "sigstore": mock.MagicMock(),
                "sigstore.sign": mock_sigstore_sign,
                "sigstore.models": mock_sigstore_models,
                "sigstore.oidc": mock_sigstore_oidc,
            },
        ):
            backend = SigstoreOIDCBackend(
                oidc_token=None,
                allow_interactive=True,
            )
            result = backend.sign(b"test-payload", "")

        self.assertTrue(result.success)
        self.assertEqual(result.signature, FAKE_BUNDLE_JSON)
        mock_sigstore_oidc.Issuer.production.assert_called_once()
        mock_issuer.identity_token.assert_called_once_with()

    def test_sign_interactive_with_custom_issuer(self):
        """Interactive flow uses configured oidc_issuer instead of production."""
        mock_identity_token = mock.MagicMock()

        mock_bundle = mock.MagicMock()
        mock_bundle.to_json.return_value = FAKE_BUNDLE_JSON

        mock_signer = mock.MagicMock()
        mock_signer.sign_artifact.return_value = mock_bundle
        mock_signer.__enter__ = mock.Mock(return_value=mock_signer)
        mock_signer.__exit__ = mock.Mock(return_value=False)

        mock_signing_context = mock.MagicMock()
        mock_signing_context.signer.return_value = mock_signer

        mock_trust_config = mock.MagicMock()
        mock_client_trust_config = mock.MagicMock()
        mock_client_trust_config.production.return_value = mock_trust_config

        mock_sigstore_sign = mock.MagicMock()
        mock_sigstore_sign.SigningContext.from_trust_config.return_value = mock_signing_context

        mock_sigstore_models = mock.MagicMock()
        mock_sigstore_models.ClientTrustConfig = mock_client_trust_config

        mock_issuer = mock.MagicMock()
        mock_issuer.identity_token.return_value = mock_identity_token

        mock_sigstore_oidc = mock.MagicMock()
        mock_sigstore_oidc.detect_credential.return_value = None
        mock_sigstore_oidc.Issuer.return_value = mock_issuer

        with mock.patch.dict(
            sys.modules,
            {
                "sigstore": mock.MagicMock(),
                "sigstore.sign": mock_sigstore_sign,
                "sigstore.models": mock_sigstore_models,
                "sigstore.oidc": mock_sigstore_oidc,
            },
        ):
            backend = SigstoreOIDCBackend(
                oidc_issuer="https://sso.corp.example.com/realms/main",
                oidc_client_id="harness-ci",
                allow_interactive=True,
            )
            result = backend.sign(b"test-payload", "")

        self.assertTrue(result.success)
        mock_sigstore_oidc.Issuer.assert_called_once_with(
            "https://sso.corp.example.com/realms/main"
        )
        mock_sigstore_oidc.Issuer.production.assert_not_called()
        mock_issuer.identity_token.assert_called_once_with(client_id="harness-ci")

    def test_sign_interactive_not_attempted_by_default(self):
        """Default allow_interactive=False skips browser flow, returns error."""
        mock_sigstore_oidc = mock.MagicMock()
        mock_sigstore_oidc.detect_credential.return_value = None

        with mock.patch.dict(
            sys.modules,
            {
                "sigstore": mock.MagicMock(),
                "sigstore.sign": mock.MagicMock(),
                "sigstore.models": mock.MagicMock(),
                "sigstore.oidc": mock_sigstore_oidc,
            },
        ):
            backend = SigstoreOIDCBackend(oidc_token=None)
            result = backend.sign(b"payload", "")

        self.assertFalse(result.success)
        self.assertIn("No OIDC token available", result.error)
        mock_sigstore_oidc.Issuer.assert_not_called()
        mock_sigstore_oidc.Issuer.production.assert_not_called()


class TestSigstoreOIDCBackendVerify(unittest.TestCase):
    @mock.patch.dict(
        sys.modules, {"sigstore": None, "sigstore.verify": None, "sigstore.models": None}
    )
    def test_verify_without_sigstore_installed(self):
        backend = SigstoreOIDCBackend(
            expected_identity="user@example.com",
            oidc_issuer="https://accounts.google.com",
        )
        result = backend.verify(b"payload", FAKE_BUNDLE_JSON, "")
        self.assertFalse(result.valid)
        self.assertIn("sigstore package not installed", result.error)

    def test_verify_missing_identity_config(self):
        backend = SigstoreOIDCBackend(expected_identity=None, oidc_issuer=None)

        mock_sigstore_verify = mock.MagicMock()
        mock_sigstore_models = mock.MagicMock()
        mock_sigstore_models.Bundle.from_json.return_value = mock.MagicMock()

        with mock.patch.dict(
            sys.modules,
            {
                "sigstore": mock.MagicMock(),
                "sigstore.verify": mock_sigstore_verify,
                "sigstore.models": mock_sigstore_models,
            },
        ):
            result = backend.verify(b"payload", FAKE_BUNDLE_JSON, "")

        self.assertFalse(result.valid)
        self.assertIn("expected_identity", result.error)
        self.assertIn("oidc_issuer", result.error)

    def test_verify_corrupt_bundle(self):
        mock_sigstore_verify = mock.MagicMock()
        mock_sigstore_models = mock.MagicMock()
        mock_sigstore_models.Bundle.from_json.side_effect = ValueError("bad JSON")

        with mock.patch.dict(
            sys.modules,
            {
                "sigstore": mock.MagicMock(),
                "sigstore.verify": mock_sigstore_verify,
                "sigstore.models": mock_sigstore_models,
            },
        ):
            backend = SigstoreOIDCBackend(
                expected_identity="user@example.com",
                oidc_issuer="https://accounts.google.com",
            )
            result = backend.verify(b"payload", "not-valid-json{{{", "")

        self.assertFalse(result.valid)
        self.assertIn("deserialize", result.error)

    def test_verify_success(self):
        mock_bundle = mock.MagicMock()
        mock_sigstore_models = mock.MagicMock()
        mock_sigstore_models.Bundle.from_json.return_value = mock_bundle

        mock_verifier = mock.MagicMock()
        mock_verifier.verify_artifact.return_value = None

        mock_sigstore_verify = mock.MagicMock()
        mock_sigstore_verify.Verifier.production.return_value = mock_verifier

        mock_policy = mock.MagicMock()
        mock_sigstore_verify.policy = mock_policy

        with mock.patch.dict(
            sys.modules,
            {
                "sigstore": mock.MagicMock(),
                "sigstore.verify": mock_sigstore_verify,
                "sigstore.verify.policy": mock_policy,
                "sigstore.models": mock_sigstore_models,
            },
        ):
            backend = SigstoreOIDCBackend(
                expected_identity="user@example.com",
                oidc_issuer="https://accounts.google.com",
            )
            result = backend.verify(b"payload", FAKE_BUNDLE_JSON, "")

        self.assertTrue(result.valid)

    def test_verify_identity_mismatch(self):
        mock_bundle = mock.MagicMock()
        mock_sigstore_models = mock.MagicMock()
        mock_sigstore_models.Bundle.from_json.return_value = mock_bundle

        mock_verifier = mock.MagicMock()
        mock_verifier.verify_artifact.side_effect = Exception(
            "Certificate identity mismatch: expected user@example.com"
        )

        mock_sigstore_verify = mock.MagicMock()
        mock_sigstore_verify.Verifier.production.return_value = mock_verifier

        mock_policy = mock.MagicMock()
        mock_sigstore_verify.policy = mock_policy

        with mock.patch.dict(
            sys.modules,
            {
                "sigstore": mock.MagicMock(),
                "sigstore.verify": mock_sigstore_verify,
                "sigstore.verify.policy": mock_policy,
                "sigstore.models": mock_sigstore_models,
            },
        ):
            backend = SigstoreOIDCBackend(
                expected_identity="user@example.com",
                oidc_issuer="https://accounts.google.com",
            )
            result = backend.verify(b"payload", FAKE_BUNDLE_JSON, "")

        self.assertFalse(result.valid)
        self.assertIn("identity mismatch", result.error)

    def test_verify_issuer_mismatch(self):
        mock_bundle = mock.MagicMock()
        mock_sigstore_models = mock.MagicMock()
        mock_sigstore_models.Bundle.from_json.return_value = mock_bundle

        mock_verifier = mock.MagicMock()
        mock_verifier.verify_artifact.side_effect = Exception(
            "Certificate issuer mismatch: expected https://accounts.google.com"
        )

        mock_sigstore_verify = mock.MagicMock()
        mock_sigstore_verify.Verifier.production.return_value = mock_verifier

        mock_policy = mock.MagicMock()
        mock_sigstore_verify.policy = mock_policy

        with mock.patch.dict(
            sys.modules,
            {
                "sigstore": mock.MagicMock(),
                "sigstore.verify": mock_sigstore_verify,
                "sigstore.verify.policy": mock_policy,
                "sigstore.models": mock_sigstore_models,
            },
        ):
            backend = SigstoreOIDCBackend(
                expected_identity="user@example.com",
                oidc_issuer="https://accounts.google.com",
            )
            result = backend.verify(b"payload", FAKE_BUNDLE_JSON, "")

        self.assertFalse(result.valid)
        self.assertIn("issuer mismatch", result.error)


class TestCustomInfrastructureURLs(unittest.TestCase):
    """Verify ca_url/tlog_url are wired through to signing/verification contexts."""

    def test_partial_url_config_errors_on_sign(self):
        backend = SigstoreOIDCBackend(
            ca_url="https://ca.example.com",
            tlog_url=None,
            oidc_token="tok",
        )
        mock_sigstore_oidc = mock.MagicMock()
        with mock.patch.dict(
            sys.modules,
            {
                "sigstore": mock.MagicMock(),
                "sigstore.sign": mock.MagicMock(),
                "sigstore.models": mock.MagicMock(),
                "sigstore.oidc": mock_sigstore_oidc,
            },
        ):
            result = backend.sign(b"payload", "")
        self.assertFalse(result.success)
        self.assertIn("both ca_url and tlog_url must be configured", result.error)

    def test_partial_url_config_errors_on_verify(self):
        backend = SigstoreOIDCBackend(
            ca_url=None,
            tlog_url="https://tlog.example.com",
            expected_identity="u@example.com",
            oidc_issuer="https://issuer.example.com",
        )
        mock_sigstore_verify = mock.MagicMock()
        mock_sigstore_models = mock.MagicMock()
        with mock.patch.dict(
            sys.modules,
            {
                "sigstore": mock.MagicMock(),
                "sigstore.verify": mock_sigstore_verify,
                "sigstore.models": mock_sigstore_models,
            },
        ):
            result = backend.verify(b"payload", FAKE_BUNDLE_JSON, "")
        self.assertFalse(result.valid)
        self.assertIn("both ca_url and tlog_url must be configured", result.error)

    def test_custom_urls_build_signing_context(self):
        """When both URLs set, _build_signing_context uses ClientTrustConfig."""
        backend = SigstoreOIDCBackend(
            ca_url="https://ca.corp.example.com",
            tlog_url="https://tlog.corp.example.com",
            oidc_token="tok",
        )
        mock_trust_config = mock.MagicMock()
        mock_client_trust_config = mock.MagicMock()
        mock_client_trust_config.from_json.return_value = mock_trust_config
        mock_signing_ctx_instance = mock.MagicMock()

        mock_sigstore_sign = mock.MagicMock()
        mock_sigstore_sign.SigningContext.from_trust_config.return_value = mock_signing_ctx_instance
        mock_sigstore_models = mock.MagicMock()
        mock_sigstore_models.ClientTrustConfig = mock_client_trust_config

        with mock.patch.dict(
            sys.modules,
            {
                "sigstore": mock.MagicMock(),
                "sigstore.sign": mock_sigstore_sign,
                "sigstore.models": mock_sigstore_models,
            },
        ):
            ctx = backend._build_signing_context()

        mock_client_trust_config.from_json.assert_called_once_with(
            '{"fulcio_url": "https://ca.corp.example.com", '
            '"rekor_url": "https://tlog.corp.example.com"}'
        )
        mock_sigstore_sign.SigningContext.from_trust_config.assert_called_once_with(
            mock_trust_config,
        )
        self.assertIs(ctx, mock_signing_ctx_instance)

    def test_custom_urls_build_verifier(self):
        """When both URLs set, _build_verifier uses ClientTrustConfig."""
        backend = SigstoreOIDCBackend(
            ca_url="https://ca.corp.example.com",
            tlog_url="https://tlog.corp.example.com",
            expected_identity="u@example.com",
            oidc_issuer="https://issuer.example.com",
        )
        mock_trust_config = mock.MagicMock()
        mock_client_trust_config = mock.MagicMock()
        mock_client_trust_config.from_urls.return_value = mock_trust_config
        mock_verifier_instance = mock.MagicMock()

        mock_sigstore_verify = mock.MagicMock()
        mock_sigstore_verify.Verifier.return_value = mock_verifier_instance
        mock_sigstore_models = mock.MagicMock()
        mock_sigstore_models.ClientTrustConfig = mock_client_trust_config

        with mock.patch.dict(
            sys.modules,
            {
                "sigstore": mock.MagicMock(),
                "sigstore.verify": mock_sigstore_verify,
                "sigstore.models": mock_sigstore_models,
            },
        ):
            v = backend._build_verifier()

        mock_client_trust_config.from_urls.assert_called_once_with(
            fulcio_url="https://ca.corp.example.com",
            rekor_url="https://tlog.corp.example.com",
        )
        mock_sigstore_verify.Verifier.assert_called_once_with(
            trust_config=mock_trust_config,
        )
        self.assertIs(v, mock_verifier_instance)

    def test_no_custom_urls_uses_production(self):
        """When neither URL is set, uses production defaults."""
        backend = SigstoreOIDCBackend(ca_url=None, tlog_url=None)

        mock_trust_config = mock.MagicMock()
        mock_client_trust_config = mock.MagicMock()
        mock_client_trust_config.production.return_value = mock_trust_config

        mock_sigstore_sign = mock.MagicMock()
        mock_production_ctx = mock.MagicMock()
        mock_sigstore_sign.SigningContext.from_trust_config.return_value = mock_production_ctx

        mock_sigstore_models = mock.MagicMock()
        mock_sigstore_models.ClientTrustConfig = mock_client_trust_config

        with mock.patch.dict(
            sys.modules,
            {
                "sigstore": mock.MagicMock(),
                "sigstore.sign": mock_sigstore_sign,
                "sigstore.models": mock_sigstore_models,
            },
        ):
            ctx = backend._build_signing_context()

        mock_client_trust_config.production.assert_called_once()
        mock_sigstore_sign.SigningContext.from_trust_config.assert_called_once_with(
            mock_trust_config,
        )
        self.assertIs(ctx, mock_production_ctx)

    def test_sign_with_custom_urls_end_to_end(self):
        """Full sign flow with custom URLs verifies context construction."""
        mock_bundle = mock.MagicMock()
        mock_bundle.to_json.return_value = FAKE_BUNDLE_JSON

        mock_signer = mock.MagicMock()
        mock_signer.sign_artifact.return_value = mock_bundle
        mock_signer.__enter__ = mock.Mock(return_value=mock_signer)
        mock_signer.__exit__ = mock.Mock(return_value=False)

        mock_signing_ctx = mock.MagicMock()
        mock_signing_ctx.signer.return_value = mock_signer

        mock_trust_config = mock.MagicMock()
        mock_client_trust_config = mock.MagicMock()
        mock_client_trust_config.from_json.return_value = mock_trust_config

        mock_sigstore_sign = mock.MagicMock()
        mock_sigstore_sign.SigningContext.from_trust_config.return_value = mock_signing_ctx

        mock_sigstore_models = mock.MagicMock()
        mock_sigstore_models.ClientTrustConfig = mock_client_trust_config

        mock_sigstore_oidc = mock.MagicMock()
        mock_sigstore_oidc.IdentityToken.return_value = mock.MagicMock()

        with mock.patch.dict(
            sys.modules,
            {
                "sigstore": mock.MagicMock(),
                "sigstore.sign": mock_sigstore_sign,
                "sigstore.models": mock_sigstore_models,
                "sigstore.oidc": mock_sigstore_oidc,
            },
        ):
            backend = SigstoreOIDCBackend(
                oidc_token="my-token",
                ca_url="https://ca.internal.example.com",
                tlog_url="https://tlog.internal.example.com",
            )
            result = backend.sign(b"test-payload", "")

        self.assertTrue(result.success)
        self.assertEqual(result.signature, FAKE_BUNDLE_JSON)
        mock_client_trust_config.from_json.assert_called_once_with(
            '{"fulcio_url": "https://ca.internal.example.com", '
            '"rekor_url": "https://tlog.internal.example.com"}'
        )
        mock_client_trust_config.production.assert_not_called()
        mock_sigstore_sign.SigningContext.from_trust_config.assert_called_once_with(
            mock_trust_config,
        )


if __name__ == "__main__":
    unittest.main()
