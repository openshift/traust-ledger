"""A machine identity must not decay into a human one.

Four defects found reviewing 0.18.0 before it was used, all the same shape: the
*kind* was re-derived from the immediate invocation while the *identity* was
restored from remembered state, so ordinary use silently downgraded automation to
a named person — which is precisely the misattribution machine identity exists to
prevent, arriving by the path least likely to be watched.

1. `ledger auth local` with no arguments (the documented refresh, which prints
   "refreshed") reset kind to human and lower-cased the version string.
2. `_auto_mint_local_token` — the fallback `resolve_token` reaches when a stored
   credential **expires** — always minted human, so a 7-day-old machine identity
   flipped mid-campaign.
3. `ledger auth service-account` reported `Kind: machine` for an opaque token
   whose claims it could not read: a false assurance about the thing being checked.
4. It indexed `response["access_token"]` unguarded after already saving config.
"""

from __future__ import annotations

import jwt
import pytest

from traust_ledger.auth.local import ensure_local_keypair, mint_local_token

MACHINE_ID = "triage/0.32.0-57f1EF1"


def _claims(token: str) -> dict:
    return jwt.decode(token, options={"verify_signature": False})


def _is_machine(token: str) -> bool:
    c = _claims(token)
    return bool(c.get("azp")) and not c.get("email")


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("LEDGER_TOKEN", raising=False)
    monkeypatch.delenv("LEDGER_TOKEN_PATH", raising=False)
    monkeypatch.delenv("LEDGER_LOCAL_MACHINE", raising=False)
    return tmp_path


def _run_auth_local(**kwargs):
    import argparse

    from traust_ledger.cli.identity.commands import cmd_auth_local

    args = argparse.Namespace(
        identity=kwargs.get("identity"),
        machine=kwargs.get("machine", False),
        human=kwargs.get("human", False),
    )
    return cmd_auth_local(args)


def _stored_token() -> str:
    from traust_ledger.cli.identity.config import load_credentials

    return load_credentials()["access_token"]


def test_bare_remint_keeps_the_machine_kind(home):
    """Defect 1 — the refresh idiom must not downgrade."""
    assert _run_auth_local(identity=MACHINE_ID, machine=True) == 0
    assert _is_machine(_stored_token())

    assert _run_auth_local() == 0  # `ledger auth local`, no flags
    assert _is_machine(_stored_token()), "bare re-mint downgraded machine to human"


def test_bare_remint_does_not_case_fold_a_machine_name(home):
    _run_auth_local(identity=MACHINE_ID, machine=True)
    _run_auth_local()
    assert _claims(_stored_token())["azp"] == MACHINE_ID


def test_explicit_human_still_downgrades(home):
    """Opting out must remain possible, just not accidental."""
    _run_auth_local(identity=MACHINE_ID, machine=True)
    assert _run_auth_local(human=True) == 0
    assert not _is_machine(_stored_token())


def test_machine_and_human_are_mutually_exclusive(home):
    assert _run_auth_local(identity=MACHINE_ID, machine=True, human=True) == 2


def test_human_identity_is_unaffected(home):
    assert _run_auth_local(identity="Someone@Example.com") == 0
    assert _claims(_stored_token())["email"] == "someone@example.com"
    _run_auth_local()
    assert not _is_machine(_stored_token())


def test_auto_mint_inherits_remembered_kind_after_expiry(home, monkeypatch):
    """Defect 2 — expiry must not change who the actor is."""
    from traust_ledger.cli.identity.config import config_dir, resolve_token

    _run_auth_local(identity="triage/0.32.0", machine=True)
    (config_dir() / "credentials.json").unlink()  # as expiry leaves it
    monkeypatch.setenv("LEDGER_LOCAL_IDENTITY", "triage/0.32.0")
    assert _is_machine(resolve_token()), "expired machine identity fell back to human"


def test_auto_mint_env_override(home, monkeypatch):
    from traust_ledger.cli.identity.config import resolve_token

    monkeypatch.setenv("LEDGER_LOCAL_IDENTITY", "scanner/2.0")
    monkeypatch.setenv("LEDGER_LOCAL_MACHINE", "1")
    assert _is_machine(resolve_token())


def test_auto_mint_defaults_to_human_for_an_unknown_identity(home, monkeypatch):
    """Inheritance is per-identity: an unrelated name must not borrow the kind."""
    from traust_ledger.cli.identity.config import resolve_token

    _run_auth_local(identity="triage/0.32.0", machine=True)
    from traust_ledger.cli.identity.config import config_dir

    (config_dir() / "credentials.json").unlink()
    monkeypatch.setenv("LEDGER_LOCAL_IDENTITY", "someone@example.com")
    assert not _is_machine(resolve_token())


def test_mint_is_human_by_default(tmp_path):
    key = ensure_local_keypair(tmp_path)
    assert not _is_machine(mint_local_token("someone@example.com", key))
