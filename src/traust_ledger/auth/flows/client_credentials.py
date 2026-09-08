"""Client-credentials flow — a service account acquires a machine token.

The other flows here authenticate a *person*: device-code prints a URL for
someone to visit, refresh renews what that person was given. Automation has no
person, and until 0.18.0 that left it borrowing one — a scheduled emitter signed
as whoever the job happened to run as, so verdicts a triage run made were
recorded against a named human who had never seen them.

This is the counterpart to ``ledger auth local --machine``: that mints a machine
token offline for an operator-run backfill on a trusted host, this obtains one
from the real identity provider for the ongoing pipeline. Both produce the same
actor shape, so consumers cannot tell which was used to *derive* identity — only
``identity_provider`` (``local`` vs ``oidc``) records the difference in strength.

**A machine token must carry no identity claim.** ``TokenVerifier._claims_to_actor``
reads ``machine`` only when the machine claim (default ``azp``) is present and the
identity claim (default ``email``) is absent; a provider configured to put an
address on a service account will therefore yield a *human* actor. That is a
provider misconfiguration and this flow says so rather than recording it, because
the failure is otherwise invisible: the write succeeds and the attribution is
quietly wrong.

The client secret is never logged, never placed on argv, and is read by the CLI
from a file or the environment.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from traust_ledger.auth._httpx import http

if TYPE_CHECKING:  # annotations only — no runtime import, no extra required
    import httpx2 as httpx


class ClientCredentialsFlow:
    """OAuth2 ``client_credentials`` grant for service accounts."""

    def __init__(self, token_endpoint: str, client_id: str, scope: str = "openid") -> None:
        self._token_endpoint = token_endpoint
        self._client_id = client_id
        self._scope = scope

    def execute(self, client_secret: str) -> dict:
        """Exchange client credentials → token response dict.

        Raises RuntimeError with the provider's own ``error_description`` when it
        refuses; an opaque failure here is indistinguishable from a typo in the
        client id, which is the common case.
        """
        if not client_secret:
            raise RuntimeError("client secret must not be empty")
        httpx = http()
        with httpx.Client(timeout=30) as client:
            response = client.post(
                self._token_endpoint,
                data={
                    "grant_type": "client_credentials",
                    "client_id": self._client_id,
                    "client_secret": client_secret,
                    "scope": self._scope,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            if response.is_success:
                return response.json()
            _raise_client_credentials_failed(response, self._client_id)
            return {}  # unreachable, satisfies type checker


def _raise_client_credentials_failed(response: httpx.Response, client_id: str) -> None:
    try:
        body = response.json()
    except ValueError:
        body = {}
    if isinstance(body, dict) and body.get("error"):
        detail = body.get("error_description") or body["error"]
        raise RuntimeError(f"client-credentials grant refused for {client_id}: {detail}")
    response.raise_for_status()
