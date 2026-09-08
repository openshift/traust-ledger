"""Integration tests for ledger CLI auth boundaries and deprecation shims."""

from __future__ import annotations

import argparse
import importlib
import json
import warnings
from pathlib import Path

import pytest

from traust_ledger._internal.identity import fingerprint
from traust_ledger.cli.commands.fingerprint import cmd_fingerprint
from traust_ledger.cli.identity import config as auth_config


def _patch_config_dir(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    cfg_dir = tmp_path / "ledger"
    monkeypatch.setattr(auth_config, "config_dir", lambda: cfg_dir)
    return cfg_dir


def test_fingerprint_stamps_without_auth(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _patch_config_dir(monkeypatch, tmp_path)
    monkeypatch.delenv("LEDGER_SERVER_URL", raising=False)

    finding = {
        "locations": [{"path": "src/main.py"}],
        "cwes": ["CWE-79"],
    }
    repo_url = "https://github.com/org/repo"
    expected_fp = fingerprint(finding, repo_url)
    report = {
        "metadata": {"repository": repo_url},
        "findings": [finding],
    }
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")

    result = cmd_fingerprint(argparse.Namespace(report_path=str(report_path)))
    assert result == 0

    updated = json.loads(report_path.read_text(encoding="utf-8"))
    assert updated["findings"][0]["fingerprint"] == expected_fp


def test_package_import_does_not_warn() -> None:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        importlib.reload(importlib.import_module("traust_ledger"))
    assert not any("deprecated" in str(w.message).lower() for w in caught)
