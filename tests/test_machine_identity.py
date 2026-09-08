"""Automation must be able to sign as a machine.

Until 0.18.0 `mint_local_token` always set both `sub` and `email`, and
`TokenVerifier._claims_to_actor` reads `machine` only when the machine claim is
present and the identity claim is absent — so every locally-minted token was a
*human* actor by construction, with no flag to change it.

The consequence was not cosmetic. Replaying triage verdicts recorded
`{"kind": "human", "identity": "<the operator>", "identity_verified": true}` on
`validity: confirmed` findings that a July triage run had adjudicated and the
operator had never seen, while the events those runs originally wrote carried
`{"kind": "machine", "identity": "triage/0.32.0-57f1ef1"}`.
"""

from __future__ import annotations

from pathlib import Path

import jwt
import pytest

from traust_ledger.auth.local import ensure_local_keypair, mint_local_token
from traust_ledger.auth.verifier import TokenVerifier, VerifierConfig
from traust_ledger.constants import ACTOR_KIND_HUMAN, ACTOR_KIND_MACHINE

MACHINE_ID = "triage/0.32.0-57f1ef1"
HUMAN_ID = "someone@example.com"


@pytest.fixture
def key(tmp_path):
    return ensure_local_keypair(tmp_path)


def _claims(token: str) -> dict:
    return jwt.decode(token, options={"verify_signature": False})


def test_machine_token_omits_the_identity_claim(key):
    """`email` present at all makes the verifier read it as a human."""
    claims = _claims(mint_local_token(MACHINE_ID, key, machine=True))
    assert claims["azp"] == MACHINE_ID
    assert "email" not in claims


def test_human_token_is_unchanged(key):
    claims = _claims(mint_local_token(HUMAN_ID, key))
    assert claims["email"] == HUMAN_ID
    assert "azp" not in claims


def test_default_is_human(key):
    """Machine identity is opt-in; omitting the flag must not change attribution."""
    assert "email" in _claims(mint_local_token(HUMAN_ID, key))


def _verify(tmp_path, token: str):
    verifier = TokenVerifier(
        VerifierConfig(jwks_path=Path(tmp_path) / "local-jwks.json", issuer="local")
    )
    return verifier.verify(token)


def test_machine_token_verifies_as_a_machine_actor(tmp_path, key):
    """The end-to-end property: claim shape in, actor kind out."""
    actor = _verify(tmp_path, mint_local_token(MACHINE_ID, key, machine=True))
    assert actor.kind == ACTOR_KIND_MACHINE
    assert actor.identity == MACHINE_ID
    assert actor.identity_provider == "local"


def test_human_token_still_verifies_as_human(tmp_path, key):
    actor = _verify(tmp_path, mint_local_token(HUMAN_ID, key))
    assert actor.kind == ACTOR_KIND_HUMAN
    assert actor.identity == HUMAN_ID


def test_machine_identity_is_not_case_folded(tmp_path, key):
    """A version string is not an address — folding it rewrites what it names."""
    ident = "triage/0.32.0-57f1EF1"
    actor = _verify(tmp_path, mint_local_token(ident, key, machine=True))
    assert actor.identity == ident


def test_empty_identity_still_refused(key):
    with pytest.raises(ValueError):
        mint_local_token("   ", key, machine=True)
