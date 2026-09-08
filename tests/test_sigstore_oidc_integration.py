#!/usr/bin/env python3
"""Integration test for SigstoreOIDCBackend with real Sigstore public-good infra.

Auto-skips when no OIDC credentials are available. To run locally:

    export LAAS_SIGNING_OIDC_TOKEN=<your-oidc-token>
    export LAAS_SIGNING_OIDC_ISSUER=https://accounts.google.com
    export LAAS_SIGNING_EXPECTED_IDENTITY=user@example.com
    python -m pytest tests/test_sigstore_oidc_integration.py -v

In GitHub Actions CI, the token is acquired automatically via ambient
credential detection (no env var needed).
"""

from __future__ import annotations

import importlib.util
import os
import sys
import unittest

import pytest

from traust_ledger._internal.integrity.signing import SigningConfig, SigstoreOIDCBackend


def _has_oidc_credentials() -> bool:
    """Check if OIDC credentials are available (explicit token or ambient)."""
    if os.environ.get("LAAS_SIGNING_OIDC_TOKEN"):
        return True
    try:
        from sigstore.oidc import detect_credential

        return detect_credential() is not None
    except (ImportError, Exception):
        return False


def _has_sigstore() -> bool:
    if "sigstore" in sys.modules:
        return sys.modules["sigstore"] is not None
    try:
        return importlib.util.find_spec("sigstore") is not None
    except (ImportError, ValueError):
        return False


@pytest.mark.skipif(not _has_sigstore(), reason="sigstore package not installed")
@pytest.mark.skipif(
    not _has_oidc_credentials(),
    reason="No OIDC credentials available (set LAAS_SIGNING_OIDC_TOKEN or run in CI)",
)
class TestSigstoreOIDCIntegration(unittest.TestCase):
    """Full round-trip sign/verify with Sigstore public-good infrastructure."""

    def setUp(self):
        config = SigningConfig.from_env()
        self.backend = SigstoreOIDCBackend(
            oidc_issuer=config.oidc_issuer,
            oidc_client_id=config.oidc_client_id,
            expected_identity=config.expected_identity,
            oidc_token=config.oidc_token,
            allow_interactive=False,
            ca_url=config.ca_url,
            tlog_url=config.tlog_url,
        )

    def test_available(self):
        self.assertTrue(self.backend.available())

    def test_sign_and_verify_round_trip(self):
        payload = b"test-merkle-root-payload-for-integration"

        sign_result = self.backend.sign(payload, "")
        self.assertTrue(sign_result.success, f"Sign failed: {sign_result.error}")
        self.assertTrue(len(sign_result.signature) > 100)

        verify_result = self.backend.verify(payload, sign_result.signature, "")
        self.assertTrue(verify_result.valid, f"Verify failed: {verify_result.error}")

    def test_verify_tampered_payload_fails(self):
        payload = b"original-payload"
        sign_result = self.backend.sign(payload, "")
        self.assertTrue(sign_result.success, f"Sign failed: {sign_result.error}")

        tampered = b"tampered-payload"
        verify_result = self.backend.verify(tampered, sign_result.signature, "")
        self.assertFalse(verify_result.valid)


if __name__ == "__main__":
    unittest.main()
