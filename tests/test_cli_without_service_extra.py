"""The CLI must import without the optional `service` extra.

Five CLI modules did `from fastapi import HTTPException` at module scope, so
`import traust_ledger.cli.commands` raised ModuleNotFoundError on any install
without the `service` extra — even though no CLI command needs a web server.

The annotation was also describing an exception that could not occur:
`submit_event` and friends raise `ServiceError` subclasses, never `HTTPException`,
and `ServiceError.detail` is the attribute the handler already read. So the fix
removed a dependency and corrected a type at once.

Same family as the 0.17.2 defect where `httpx2` and `PyJWT` sat in extras while
sitting on the import path of every write.
"""

from __future__ import annotations

import ast
import pathlib
import subprocess
import sys

import pytest

CLI_DIR = pathlib.Path(__file__).resolve().parent.parent / "traust_ledger" / "cli"


@pytest.mark.parametrize("source", sorted(CLI_DIR.rglob("*.py")), ids=lambda p: p.name)
def test_no_module_level_fastapi_import(source: pathlib.Path) -> None:
    """A web framework must never be required merely to import the CLI."""
    tree = ast.parse(source.read_text(encoding="utf-8"))
    for node in tree.body:  # module scope only
        names = []
        if isinstance(node, ast.Import):
            names = [a.name.split(".")[0] for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            names = [node.module.split(".")[0]]
        assert "fastapi" not in names, (
            f"{source.name} imports fastapi at module scope — the CLI is usable "
            f"without the `service` extra and must stay that way"
        )


BLOCKED_IMPORT_PROBE = """
import sys


class _Block:
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split(".")[0] == "fastapi":
            raise ModuleNotFoundError("No module named %r" % fullname)
        return None


sys.meta_path.insert(0, _Block())
import traust_ledger.cli.commands  # noqa: E402
import traust_ledger.cli.commands.countersign  # noqa: E402,F401
import traust_ledger.cli.errors  # noqa: E402,F401

assert hasattr(traust_ledger.cli.commands, "register_all_parsers")
print("OK")
"""


def test_cli_imports_with_fastapi_blocked() -> None:
    """In a subprocess, so blocking a module cannot leak into other tests."""
    result = subprocess.run(
        [sys.executable, "-c", BLOCKED_IMPORT_PROBE],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, f"CLI failed to import with fastapi blocked:\n{result.stderr}"
    assert "OK" in result.stdout


def test_service_error_carries_the_attribute_the_cli_prints() -> None:
    """`cli_exit_service_error` reads `.detail`; ServiceError must provide it."""
    from traust_ledger.errors import ValidationError

    exc = ValidationError(detail="probe")
    assert hasattr(exc, "detail") and exc.detail
