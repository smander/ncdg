import json
from pathlib import Path

from firmware.synthetic_conflict_loader import load_pair, list_pairs
from cdg_lib.types import EdgeLabel, SolverOutcome


BENCH = Path("firmware/synthetic_conflict")


def test_list_pairs_returns_buffer_overflow_pair_01():
    pairs = list_pairs(BENCH)
    pair_ids = [(p.theme, p.pair_id) for p in pairs]
    assert ("buffer_overflow", "pair_01") in pair_ids


def test_load_pair_builds_graph_with_dep_and_con_edges():
    pair = next(
        p for p in list_pairs(BENCH)
        if (p.theme, p.pair_id) == ("buffer_overflow", "pair_01")
    )
    cdg = load_pair(pair)

    # Four nodes: a, m, b, d
    assert len(cdg.nodes) == 4
    # DEP edges: (a, m), (m, b), (a, d)
    dep_edges = [(e.source_id, e.target_id) for e in cdg.edges
                 if e.label == EdgeLabel.DEP]
    assert ("a", "m") in dep_edges
    assert ("m", "b") in dep_edges
    assert ("a", "d") in dep_edges
    # CON edge from a -> b after a is marked UNSAT
    con_edges = [(e.source_id, e.target_id) for e in cdg.edges
                 if e.label == EdgeLabel.CON]
    assert ("a", "b") in con_edges
    # a was pre-marked UNSAT by the loader
    assert cdg.nodes["a"].outcome == SolverOutcome.UNSAT


def test_each_theme_has_a_b_trap_pair():
    for theme in ["buffer_overflow", "integer_overflow", "null_deref", "signed_unsigned"]:
        trap_found = False
        theme_dir = BENCH / theme
        for pair_dir in theme_dir.iterdir():
            if not pair_dir.is_dir():
                continue
            manifest_path = pair_dir / "manifest.json"
            if not manifest_path.is_file():
                continue
            manifest = json.loads(manifest_path.read_text())
            if manifest.get("b_should_misfire"):
                trap_found = True
                break
        assert trap_found, f"{theme} has no (b)-trap pair (b_should_misfire)"


def test_b_trap_pair_marks_a_unsat_with_no_con_edge():
    pair = next(
        p for p in list_pairs(BENCH)
        if (p.theme, p.pair_id) == ("buffer_overflow", "pair_03")
    )
    cdg = load_pair(pair)
    assert cdg.nodes["a"].outcome == SolverOutcome.UNSAT
    con_edges = [(e.source_id, e.target_id) for e in cdg.edges
                 if e.label == EdgeLabel.CON]
    assert con_edges == []
