# Synthetic Conflict-Heavy Benchmark

Hand-authored constraint pairs for the §IV-B conflict-pruning ablation.

## Layout

````
firmware/synthetic_conflict/
  {theme}/
    pair_{NN}/
      vuln.smt2          # c_A: the conflicting precondition
      intermediate.smt2  # 1+ intermediate DEP constraints
      patch.smt2         # c_B: contradicts c_A on the conjoined path
      distractor.smt2    # path-adjacent constraint, must not trigger b
      manifest.json
````

## Manifest schema

```json
{
  "theme": "buffer_overflow",
  "pair_id": "pair_01",
  "cwe": "CWE-787",
  "conflict_pair": ["a", "b"],
  "expected_outcome": "UNSAT_BY_CONFLICT",
  "nodes": [
    {"id": "a", "file": "vuln.smt2",         "skeleton": "BVUGE VAR CONST"},
    {"id": "m", "file": "intermediate.smt2", "skeleton": "EQ VAR EXPR"},
    {"id": "b", "file": "patch.smt2",        "skeleton": "BVULT VAR CONST"},
    {"id": "d", "file": "distractor.smt2",   "skeleton": "BVUGE VAR CONST"}
  ],
  "dep_edges": [["a", "m"], ["m", "b"], ["a", "d"]]
}
```

Themes: `buffer_overflow`, `integer_overflow`, `null_deref`, `signed_unsigned`.
Five pairs per theme = 20 total.
