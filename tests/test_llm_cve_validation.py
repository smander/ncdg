from pathlib import Path

import pytest

from scripts.validate_llm_cves import validate_record, validate_corpus


def test_valid_record_passes():
    rec = {
        "cve_id": "CVE-TEST-0001",
        "cwe": "CWE-787",
        "vulnerable_constraint": "len > 1024",
        "patched_constraint": "len > 65535",
        "vars": {"len": "bv16"},
        "label": "same_bug",
    }
    ok, reason = validate_record(rec)
    assert ok, f"expected pass, got: {reason}"


def test_record_with_no_change_fails():
    rec = {
        "cve_id": "CVE-TEST-9999",
        "cwe": "CWE-787",
        "vulnerable_constraint": "x < 0",
        "patched_constraint": "x < 0",
        "vars": {"x": "bv32"},
        "label": "same_bug",
    }
    ok, reason = validate_record(rec)
    assert not ok
    assert "identical" in reason.lower() or "no change" in reason.lower()


def test_unparseable_record_fails():
    rec = {
        "cve_id": "CVE-TEST-9998",
        "cwe": "CWE-787",
        "vulnerable_constraint": "true",
        "patched_constraint": "false",
        "vars": {},
        "label": "same_bug",
    }
    ok, reason = validate_record(rec)
    assert not ok


def test_validate_corpus_drops_bad_records(tmp_path):
    fixture = Path("tests/fixtures/sample_llm_cves.jsonl")
    out = tmp_path / "validated.jsonl"
    kept, dropped = validate_corpus(fixture, out)
    # 3 valid + 2 broken in the fixture
    assert kept == 3
    assert dropped == 2
    lines = out.read_text().strip().splitlines()
    assert len(lines) == 3


def test_missing_required_field_fails():
    rec = {
        "cve_id": "CVE-TEST-0002",
        # missing cwe, vulnerable_constraint, patched_constraint, vars
    }
    ok, reason = validate_record(rec)
    assert not ok
    assert "missing" in reason.lower() or "field" in reason.lower()
