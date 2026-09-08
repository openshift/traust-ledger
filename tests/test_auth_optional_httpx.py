"""`traust_ledger.auth` must import without the optional `cli` extra.

Regression for the 0.17.1 breakage: `auth/discovery.py`, `auth/flows/refresh.py`
and `auth/flows/device_code.py` did `import httpx2 as httpx` at module scope,
but `httpx2` ships only in the `cli` extra. Since `LedgerClient` →
`auth.config` → `auth.discovery` is on the path of every authenticated
write, a plain `traust-ledger` install could not append an event:

    ModuleNotFoundError: No module named 'httpx2'

That took out `traust-engine`'s `LedgerService` and all 25 harness call sites,
including for locally-minted tokens that make no network call whatsoever.
"""

from __future__ import annotations

import ast
import pathlib
import subprocess
import sys

import pytest

AUTH_DIR = pathlib.Path(__file__).resolve().parent.parent / "traust_ledger" / "auth"


def _module_level_imports(path: pathlib.Path) -> set[str]:
    """Names imported at module scope (nested/function-level imports excluded)."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in tree.body:  # module scope only — the whole point
        if isinstance(node, ast.Import):
            names.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module.split(".")[0])
    return names


@pytest.mark.parametrize("source", sorted(AUTH_DIR.rglob("*.py")), ids=lambda p: p.name)
def test_no_module_level_httpx_import(source: pathlib.Path) -> None:
    """An HTTP client must never be required merely to import the auth package."""
    assert "httpx2" not in _module_level_imports(source), (
        f"{source.name} imports httpx2 at module scope; import it inside the "
        "function that makes the network call (see traust_ledger.auth._httpx)"
    )


_BLOCKED_IMPORT_PROBE = """
import sys


class _Block:
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split(".")[0] == "httpx2":
            raise ModuleNotFoundError("No module named %r" % fullname)
        return None


sys.meta_path.insert(0, _Block())
import traust_ledger.auth  # noqa: E402

assert hasattr(traust_ledger.auth, "TokenVerifier")

from traust_ledger.auth._httpx import http  # noqa: E402

try:
    http()
except RuntimeError as exc:
    assert "traust-ledger[cli]" in str(exc), exc
else:  # pragma: no cover - httpx2 was reachable despite the block
    raise AssertionError("http() did not raise with httpx2 blocked")

print("OK")
"""


def test_auth_imports_and_fails_helpfully_without_httpx2() -> None:
    """Import `traust_ledger.auth` with httpx2 blocked, in a subprocess.

    Deliberately *not* done in-process. Blocking a module means deleting and
    re-importing `traust_ledger.auth*`, and restoring `sys.modules` afterwards does
    not restore the parent package's submodule attributes — so `traust_ledger.auth`
    was left without `.config`/`.flows`, and unrelated tests later in the session
    failed to resolve monkeypatch targets. It broke two different test modules on
    two separate occasions before being isolated properly. A subprocess cannot
    leak, which is the only guarantee worth relying on here.
    """
    result = subprocess.run(
        [sys.executable, "-c", _BLOCKED_IMPORT_PROBE],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, (
        f"importing traust_ledger.auth without httpx2 failed:\n{result.stderr}"
    )
    assert "OK" in result.stdout
