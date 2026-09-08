"""OIDC discovery — shared by CLI device-code flow and token verification setup."""

from __future__ import annotations

from dataclasses import dataclass

from traust_ledger.auth._httpx import http


@dataclass(frozen=True)
class OIDCMetadata:
    issuer: str
    jwks_uri: str
    token_endpoint: str
    device_authorization_endpoint: str | None = None


def discover_oidc(issuer: str, *, timeout: float = 30.0) -> OIDCMetadata:
    """Fetch OIDC discovery document and return parsed metadata.

    Raises RuntimeError if required fields are missing.
    """
    httpx = http()
    discovery_url = f"{issuer.rstrip('/')}/.well-known/openid-configuration"
    with httpx.Client(timeout=timeout) as client:
        response = client.get(discovery_url)
        response.raise_for_status()
        metadata = response.json()

    jwks_uri = metadata.get("jwks_uri")
    token_endpoint = metadata.get("token_endpoint")
    if not jwks_uri:
        raise RuntimeError("OIDC provider does not publish jwks_uri")
    if not token_endpoint:
        raise RuntimeError("OIDC provider does not publish token_endpoint")

    return OIDCMetadata(
        issuer=metadata.get("issuer", issuer),
        jwks_uri=jwks_uri,
        token_endpoint=token_endpoint,
        device_authorization_endpoint=metadata.get("device_authorization_endpoint"),
    )
