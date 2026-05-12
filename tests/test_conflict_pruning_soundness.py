"""Re-validate every UNSAT_BY_CONFLICT verdict by directly calling Z3 on
the conjunction (path /\\ formula). Policies (a) and (c) must never disagree.
Policy (b) may disagree on the (b)-trap pairs.
"""

from pathlib import Path

import pytest
import z3

from cdg_lib.solver import solve
from cdg_lib.types import SolverOutcome
from firmware.synthetic_conflict_loader import list_pairs, load_pair


BENCH = Path("firmware/synthetic_conflict")


def _z3_conjunction_is_unsat(*smt2_texts: str) -> bool:
    solver = z3.Solver()
    for text in smt2_texts:
        solver.add(z3.parse_smt2_string(text))
    return solver.check() == z3.unsat


@pytest.mark.parametrize("pair", list_pairs(BENCH), ids=lambda p: f"{p.theme}/{p.pair_id}")
@pytest.mark.parametrize("policy,path_source", [
    ("a", "i"), ("a", "ii"), ("a", "iii"), ("c", "i"),
])
def test_sound_policies_never_falsely_prune(pair, policy, path_source):
    cdg = load_pair(pair)
    explicit = ["a"] if policy == "a" and path_source in ("ii", "iii") else None
    outcome, _ = solve(
        cdg, "b",
        con_policy=policy,
        path_source=path_source,
        path_condition=explicit,
    )
    if outcome != SolverOutcome.UNSAT_BY_CONFLICT:
        return  # nothing pruned, nothing to validate
    a_text = cdg.nodes["a"].formula
    b_text = cdg.nodes["b"].formula
    assert _z3_conjunction_is_unsat(a_text, b_text), (
        f"policy {policy}/{path_source} falsely pruned "
        f"{pair.theme}/{pair.pair_id}: a /\\ b is satisfiable per Z3"
    )
