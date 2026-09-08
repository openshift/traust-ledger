"""traust_ledger.auth.directory — optional employee-directory cross-check.

Runs a real subprocess for the ScriptDirectory cases (a tiny script written
to tmp_path); the LedgerClient cases use a stub verifier so no token is
needed.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest
from traust_contracts.v1.models.layer import LayerActor

from traust_ledger.auth.directory import (
    DIRECTORY_COMMAND_ENV,
    DirectoryRefusedError,
    DirectoryUnavailableError,
    ScriptDirectory,
    apply_directory,
    load_directory,
)
from traust_ledger.client import LedgerClient, LedgerError

HUMAN = LayerActor(kind="human", identity="alice", identity_verified=True, identity_provider="oidc")
BOT = LayerActor(kind="machine", identity="triage/1.0", identity_verified=True)


def _script(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "dir.py"
    p.write_text("#!/usr/bin/env python3\nimport sys\n" + body)
    p.chmod(p.stat().st_mode | stat.S_IEXEC)
    return p


# statuses keyed by the uid the script is asked about
TABLE = """
table = {"alice": "active", "bob": "terminated", "carol": "contingent"}
uid = sys.argv[1]
print("noise line that mentions active employee")   # must not match
print(f"RESULT uid={uid} status={table.get(uid, 'not_found')} auth=lookup")
"""


@pytest.mark.parametrize(
    "uid,expected",
    [("alice", "active"), ("bob", "terminated"), ("carol", "contingent"), ("zed", "not_found")],
)
def test_script_directory_parses_result_line(tmp_path, uid, expected):
    d = ScriptDirectory([sys.executable, str(_script(tmp_path, TABLE))])
    assert d.is_active(uid) == expected


def test_script_directory_exact_uid_match_not_substring(tmp_path):
    # a line for "alice" must not answer for "alice2"
    d = ScriptDirectory([sys.executable, str(_script(tmp_path, TABLE))])
    assert d.is_active("alice2") == "not_found"


@pytest.mark.parametrize(
    "body",
    [
        "sys.exit(3)",  # non-zero exit
        "print('no result line here')",  # no RESULT line
        "print('RESULT uid=someone-else status=active')",  # wrong uid
    ],
)
def test_script_directory_fails_closed_as_unavailable(tmp_path, body):
    d = ScriptDirectory([sys.executable, str(_script(tmp_path, body))])
    assert d.is_active("alice") == "unavailable"


def test_script_directory_timeout_is_unavailable(tmp_path):
    d = ScriptDirectory(
        [sys.executable, str(_script(tmp_path, "import time; time.sleep(5)"))], timeout=0.5
    )
    assert d.is_active("alice") == "unavailable"


def test_script_directory_rejects_identity_with_whitespace(tmp_path):
    d = ScriptDirectory([sys.executable, str(_script(tmp_path, TABLE))])
    assert d.is_active("alice --flag") == "not_found"


def test_load_directory_unset_is_none():
    assert load_directory({}) is None
    assert load_directory({DIRECTORY_COMMAND_ENV: "   "}) is None


def test_load_directory_builds_script_directory(tmp_path):
    script = _script(tmp_path, TABLE)
    d = load_directory({DIRECTORY_COMMAND_ENV: f"{sys.executable} {script}"})
    assert isinstance(d, ScriptDirectory)
    assert d.command == [sys.executable, str(script)]
    assert d.is_active("alice") == "active"


@pytest.mark.parametrize(
    "value",
    [
        "/nonexistent/program --x",
        f"{sys.executable} /nonexistent/script.py",
        "'unterminated quote",
    ],
)
def test_load_directory_misconfiguration_fails_closed(value):
    with pytest.raises(DirectoryUnavailableError):
        load_directory({DIRECTORY_COMMAND_ENV: value})


def test_apply_directory_noop_without_directory_or_for_machines(tmp_path):
    assert apply_directory(HUMAN, None) is HUMAN
    d = ScriptDirectory([sys.executable, str(_script(tmp_path, "sys.exit(1)"))])
    assert apply_directory(BOT, d) is BOT  # machines are never cross-checked


def test_apply_directory_stamps_active_and_refuses_others(tmp_path):
    d = ScriptDirectory([sys.executable, str(_script(tmp_path, TABLE))])
    out = apply_directory(HUMAN, d)
    assert out.employee_status == "active"
    assert out.identity == "alice"
    for uid in ("bob", "carol", "zed"):
        with pytest.raises(DirectoryRefusedError) as ei:
            apply_directory(HUMAN.model_copy(update={"identity": uid}), d)
        assert uid in ei.value.detail


# --------------------------------------------------------------------------
# LedgerClient integration
# --------------------------------------------------------------------------


class _StubVerifier:
    def __init__(self, actor: LayerActor) -> None:
        self._actor = actor

    def verify(self, token: str) -> LayerActor:
        return self._actor


def _client(tmp_path: Path, actor: LayerActor, **kw) -> LedgerClient:
    from traust_ledger._internal.integrity.signing import SigningConfig

    return LedgerClient(
        token="stub",
        verifier=_StubVerifier(actor),
        data_dir=str(tmp_path / "data"),
        signing_config=SigningConfig(method="none"),
        signing_required=False,
        **kw,
    )


def test_client_actor_without_directory_is_the_token_actor(tmp_path, monkeypatch):
    monkeypatch.delenv(DIRECTORY_COMMAND_ENV, raising=False)
    c = _client(tmp_path, HUMAN)
    assert c.actor().identity == "alice"
    assert c.actor().employee_status is None


def test_client_picks_up_deployment_directory_from_env(tmp_path, monkeypatch):
    script = _script(tmp_path, TABLE)
    monkeypatch.setenv(DIRECTORY_COMMAND_ENV, f"{sys.executable} {script}")
    assert _client(tmp_path, HUMAN).actor().employee_status == "active"
    with pytest.raises(LedgerError, match="terminated"):
        _client(tmp_path, HUMAN.model_copy(update={"identity": "bob"})).actor()


def test_client_explicit_directory_and_explicit_none(tmp_path, monkeypatch):
    script = _script(tmp_path, TABLE)
    monkeypatch.setenv(DIRECTORY_COMMAND_ENV, f"{sys.executable} {script}")
    bob = HUMAN.model_copy(update={"identity": "bob"})
    # False disables the env directory
    assert _client(tmp_path, bob, directory=False).actor().identity == "bob"
    # an explicit directory object wins over env
    (tmp_path / "other").mkdir()
    d = ScriptDirectory([sys.executable, str(_script(tmp_path / "other", TABLE))])
    with pytest.raises(LedgerError, match="terminated"):
        _client(tmp_path, bob, directory=d).actor()


def test_client_misconfigured_directory_fails_at_construction(tmp_path, monkeypatch):
    monkeypatch.setenv(DIRECTORY_COMMAND_ENV, "/nonexistent/dir-check")
    with pytest.raises(DirectoryUnavailableError):
        _client(tmp_path, HUMAN)


def test_submit_refused_for_terminated_signer(tmp_path, monkeypatch):
    """The stamped-actor path: submit never reaches the writer when the
    directory refuses — no layer is touched."""
    script = _script(tmp_path, TABLE)
    monkeypatch.setenv(DIRECTORY_COMMAND_ENV, f"{sys.executable} {script}")
    bob = HUMAN.model_copy(update={"identity": "bob"})
    c = _client(tmp_path, bob)
    with pytest.raises(LedgerError, match="terminated"):
        c.submit("layer-x", [])
    assert not (tmp_path / "data").exists() or not list((tmp_path / "data").glob("*.json"))
    assert os.environ.get(DIRECTORY_COMMAND_ENV)  # sanity: env was set for this test
