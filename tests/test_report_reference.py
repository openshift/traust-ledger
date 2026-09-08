"""Content-addressed report reference (plan §4.4.0 step 1)."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from traust_ledger._internal.reports import (
    check_report_digest,
    report_sha256,
    stamp_report_reference,
)


def _report(tmp_path: Path, text: str = '{"findings": []}\n') -> Path:
    p = tmp_path / "repo-security-audit.json"
    p.write_text(text, encoding="utf-8")
    return p


def test_digest_is_over_bytes_not_a_reserialization(tmp_path):
    """The corpus is mixed on ensure_ascii; hashing a parsed dict would make the
    digest depend on which producer wrote the file."""
    escaped = _report(tmp_path, '{"title": "a \\u2014 b"}\n')
    literal = tmp_path / "other-security-audit.json"
    literal.write_text('{"title": "a — b"}\n', encoding="utf-8")

    assert json.loads(escaped.read_text()) == json.loads(literal.read_text())
    assert report_sha256(escaped) != report_sha256(literal)


def test_stamp_is_idempotent(tmp_path):
    report = _report(tmp_path)
    layer = {"metadata": {}}
    assert stamp_report_reference(layer, report) is True
    assert stamp_report_reference(layer, report) is False
    assert layer["metadata"]["audit_report_sha256"] == report_sha256(report)


def test_stamp_records_an_opaque_ref(tmp_path):
    layer = {"metadata": {}}
    stamp_report_reference(layer, _report(tmp_path), ref="s3://reports/abc/def.json")
    assert layer["metadata"]["audit_report_ref"] == "s3://reports/abc/def.json"


def test_absent_digest_is_not_a_failure(tmp_path):
    """8,508 layers predate the field; an old layer is not evidence of tampering."""
    assert check_report_digest({"metadata": {}}, _report(tmp_path)) is None


def test_rewritten_report_is_surfaced_not_healed(tmp_path):
    report = _report(tmp_path)
    layer = {"metadata": {}}
    stamp_report_reference(layer, report)

    report.write_text('{"findings": [], "note": "re-audited"}\n', encoding="utf-8")

    msg = check_report_digest(layer, report)
    assert msg and "does not match" in msg
    assert "re-record it" in msg
    # unchanged: the checker reports, it does not repair
    assert layer["metadata"]["audit_report_sha256"] == report_sha256(b'{"findings": []}\n')
