"""`VERSION` and `pyproject.toml` must agree.

The version is stored twice, and a release that bumps only `VERSION` publishes a
tag whose distribution metadata reports the *previous* version. That has now
happened twice: 0.13.0 shipped that way, and 0.17.2 again on 2026-08-28 — the
tag and source were correct while `importlib.metadata.version("traust-ledger")`
still said 0.17.1, so `traust-ledger>=0.17.2` looked unsatisfied to every consumer
and drift checks reported a version skew that no amount of syncing would clear.
"""

from __future__ import annotations

import pathlib
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent


def test_version_file_matches_pyproject() -> None:
    version_file = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert pyproject["project"]["version"] == version_file, (
        f"VERSION says {version_file} but pyproject.toml says "
        f"{pyproject['project']['version']} — bump both, or the release ships "
        "metadata for the previous version"
    )
