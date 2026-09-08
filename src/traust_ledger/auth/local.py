"""Local identity — keypair generation and JWT minting for CLI adoption.

Provides frictionless local authentication without an external OIDC provider.
The user provides an identity (email) and gets a locally-signed JWT that the
existing TokenVerifier can validate against a file-based JWKS.

Tokens carry ``iss=local`` and ``identity_provider=local`` so downstream
consumers can distinguish local attestation from external OIDC.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import jwt
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)

_LOCAL_KEY_FILE = "local-key.pem"
_LOCAL_JWKS_FILE = "local-jwks.json"
_TOKEN_LIFETIME_SECONDS = 7 * 24 * 3600  # 7 days

LOCAL_ISSUER = "local"


def ensure_local_keypair(config_dir: Path) -> ec.EllipticCurvePrivateKey:
    """Return the local signing key, generating one if it doesn't exist.

    Side effect: writes ``local-jwks.json`` alongside the key so that
    ``TokenVerifier`` can load the public key for verification.
    """
    key_path = config_dir / _LOCAL_KEY_FILE
    jwks_path = config_dir / _LOCAL_JWKS_FILE

    if key_path.is_file():
        try:
            key_data = key_path.read_bytes()
            private_key = load_pem_private_key(key_data, password=None)
        except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
            raise RuntimeError(
                f"corrupt local key at {key_path} — delete it and re-run `ledger auth local`: {exc}"
            ) from exc
        if not isinstance(private_key, ec.EllipticCurvePrivateKey):
            raise TypeError("local-key.pem is not an EC key")
        if not jwks_path.is_file():
            _write_jwks(jwks_path, private_key)
        return private_key

    private_key = ec.generate_private_key(ec.SECP256R1())
    config_dir.mkdir(mode=0o700, parents=True, exist_ok=True)

    pem = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    fd = os.open(str(key_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, pem)
    finally:
        os.close(fd)

    _write_jwks(jwks_path, private_key)
    return private_key


def _write_jwks(jwks_path: Path, private_key: ec.EllipticCurvePrivateKey) -> None:
    algo = jwt.algorithms.ECAlgorithm(jwt.algorithms.ECAlgorithm.SHA256)
    jwk_dict = algo.to_jwk(private_key.public_key(), as_dict=True)
    jwk_dict["use"] = "sig"
    jwk_dict["kid"] = "local-1"
    jwks_doc = {"keys": [jwk_dict]}
    jwks_path.write_text(json.dumps(jwks_doc, indent=2) + "\n", encoding="utf-8")


def mint_local_token(
    identity: str,
    private_key: ec.EllipticCurvePrivateKey,
    *,
    machine: bool = False,
) -> str:
    """Mint a locally-signed JWT for the given identity.

    ``machine=True`` mints a *machine* actor instead of a human one. The
    distinction is made by claim shape, not by a field:
    ``TokenVerifier._claims_to_actor`` reads ``machine`` only when the machine
    claim (default ``azp``) is present **and** the identity claim (default
    ``email``) is absent — so a machine token must omit ``email`` entirely.

    This existed only in the human shape until 0.18.0, which meant automated
    emission signed as whoever ran it. Replaying July's triage verdicts stamped
    a named person as a `human` actor onto `validity: confirmed` findings they
    had never seen, while the events those runs originally wrote carried
    ``{"kind": "machine", "identity": "triage/<version>"}``. There was no flag
    to fix it: every locally-minted token was human by construction.

    For a machine, ``identity`` is the automation's name — ``triage/0.32.0``,
    not an address.
    """
    if not identity or not identity.strip():
        raise ValueError("identity must not be empty")
    now = time.time()
    payload = {
        "sub": identity,
        "iss": LOCAL_ISSUER,
        "iat": int(now),
        "exp": int(now + _TOKEN_LIFETIME_SECONDS),
    }
    # azp for a machine, email for a human — never both, or the verifier reads
    # the identity claim first and calls it human.
    payload["azp" if machine else "email"] = identity
    return jwt.encode(
        payload,
        private_key,
        algorithm="ES256",
        headers={"kid": "local-1"},
    )


def local_jwks_path(config_dir: Path) -> Path | None:
    """Return the JWKS path if local auth has been set up."""
    p = config_dir / _LOCAL_JWKS_FILE
    return p if p.is_file() else None
