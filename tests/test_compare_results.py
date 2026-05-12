"""Unit tests for the reproducibility-verifier comparator."""

import json
from pathlib import Path

import pytest


def _import():
    """Import the comparator. Skips if the script isn't on the path yet."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "compare_results", "scripts/compare_results.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_walk_identical_dicts_no_mismatch():
    cr = _import()
    mismatches = []
    cr._walk("root", {"a": 1, "b": 2}, {"a": 1, "b": 2}, mismatches)
    assert mismatches == []


def test_walk_int_differs_records_mismatch():
    cr = _import()
    mismatches = []
    cr._walk("root", {"x": 5}, {"x": 6}, mismatches)
    assert len(mismatches) == 1
    assert "root.x" in mismatches[0]
    assert "5" in mismatches[0] and "6" in mismatches[0]


def test_walk_wall_clock_key_ignored():
    cr = _import()
    mismatches = []
    cr._walk("root", {"wall_clock_s": 1.5, "pruned": 16},
             {"wall_clock_s": 9.9, "pruned": 16}, mismatches)
    assert mismatches == []


def test_walk_missing_key_in_candidate_records_mismatch():
    cr = _import()
    mismatches = []
    cr._walk("root", {"a": 1, "b": 2}, {"a": 1}, mismatches)
    assert len(mismatches) == 1
    assert "root.b" in mismatches[0]
    assert "missing" in mismatches[0].lower()


def test_walk_list_length_mismatch():
    cr = _import()
    mismatches = []
    cr._walk("root", [1, 2, 3], [1, 2], mismatches)
    assert len(mismatches) == 1
    assert "list length" in mismatches[0]


def test_walk_list_element_mismatch():
    cr = _import()
    mismatches = []
    cr._walk("root", [{"v": 1}], [{"v": 2}], mismatches)
    assert len(mismatches) == 1
    assert "root[0].v" in mismatches[0]


def test_walk_type_mismatch_records():
    cr = _import()
    mismatches = []
    cr._walk("root", {"a": 1}, "not-a-dict", mismatches)
    assert len(mismatches) == 1
    assert "type mismatch" in mismatches[0]


def test_wall_clock_keys_includes_common_variants():
    cr = _import()
    assert "wall_clock_s" in cr.WALL_CLOCK_KEYS
    assert "elapsed" in cr.WALL_CLOCK_KEYS
    assert "duration" in cr.WALL_CLOCK_KEYS
    assert "seconds" in cr.WALL_CLOCK_KEYS
