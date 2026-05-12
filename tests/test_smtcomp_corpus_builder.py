import json
from pathlib import Path

import pytest

from scripts.build_smtcomp_corpus import build_corpus


@pytest.fixture
def fixture_dir():
    return Path(__file__).parent / "fixtures" / "sample_smtcomp"


def test_build_corpus_emits_one_record_per_file(fixture_dir, tmp_path):
    out = tmp_path / "out.jsonl"
    n = build_corpus(fixture_dir, out)
    assert n == 5
    lines = out.read_text().splitlines()
    assert len(lines) == 5


def test_records_have_required_fields(fixture_dir, tmp_path):
    out = tmp_path / "out.jsonl"
    build_corpus(fixture_dir, out)
    records = [json.loads(line) for line in out.read_text().splitlines()]
    for rec in records:
        assert "smtlib" in rec
        assert "skeleton" in rec
        assert "ops" in rec
        assert isinstance(rec["smtlib"], str)
        assert isinstance(rec["skeleton"], str)
        assert isinstance(rec["ops"], list)


def test_skeleton_replaces_constants_with_token(fixture_dir, tmp_path):
    out = tmp_path / "out.jsonl"
    build_corpus(fixture_dir, out)
    records = [json.loads(line) for line in out.read_text().splitlines()]
    for rec in records:
        # No raw hex constants should remain in the skeleton
        assert "#x" not in rec["skeleton"]
        assert "CONST" in rec["skeleton"]


def test_ops_field_lists_smtlib_operators(fixture_dir, tmp_path):
    out = tmp_path / "out.jsonl"
    build_corpus(fixture_dir, out)
    records = [json.loads(line) for line in out.read_text().splitlines()]
    bvult_seen = False
    for rec in records:
        if "bvult" in rec["ops"]:
            bvult_seen = True
            break
    assert bvult_seen, "bvult should appear in at least one fixture"


def test_skips_files_without_assert(tmp_path):
    """Files with no (assert ...) clauses produce no records."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "trivial.smt2").write_text("(set-logic QF_BV)\n(check-sat)\n(exit)\n")
    out = tmp_path / "out.jsonl"
    n = build_corpus(src, out)
    assert n == 0
