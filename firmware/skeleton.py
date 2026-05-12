"""Canonical skeleton extraction from claripy ASTs.

Produces a string with all variables collapsed to VAR and all constants to CONST,
preserving operator structure. Used to bucket structurally-equivalent constraints
for the CDG SIM-edge index.
"""

from typing import Any


def compute_skeleton(ast: Any) -> str:
    """Return canonical skeleton for a claripy AST.

    Variables -> VAR, concrete values -> CONST. Operator structure preserved.
    Idempotent on already-canonical strings (unit-test invariant).
    """
    op = getattr(ast, "op", None)
    if op is None:
        return "CONST"

    if op == "BVS":
        return "VAR"
    if op == "BVV":
        return "CONST"

    args = getattr(ast, "args", ())
    rendered = [compute_skeleton(a) if hasattr(a, "op") else _atom_token(a)
                for a in args]
    return _format_op(op, rendered)


def _atom_token(value: Any) -> str:
    """Non-AST argument (Python int, etc.) -- treat as CONST."""
    if isinstance(value, int):
        return "CONST"
    if isinstance(value, str):
        return "CONST"
    return "CONST"


# Maps claripy op names to infix display symbols.
# NOTE: claripy uses unsigned comparison ops (ULT, ULE, UGT, UGE) for Python
# operator overloads (<, <=, >, >=) on BV expressions. __lt__ etc. are NOT used.
# We use 'u<', 'u<=', etc. to explicitly mark these as unsigned, distinguishing
# from signed comparison operators (SLT, SLE, etc.).
_INFIX_OPS = {
    # Unsigned comparisons (used by Python operator overloads on BVS/BVV)
    "ULT": "u<", "ULE": "u<=", "UGT": "u>", "UGE": "u>=",
    # Signed comparisons (explicit claripy.SLT etc.)
    "SLT": "s<", "SLE": "s<=", "SGT": "s>", "SGE": "s>=",
    # Equality (uses dunder names in claripy)
    "__eq__": "==", "__ne__": "!=",
    # Arithmetic
    "__add__": "+", "__sub__": "-",
    "__mul__": "*", "__floordiv__": "/",
    # Bitwise
    "__and__": "&", "__or__": "|", "__xor__": "^",
    "__lshift__": "<<", "__rshift__": ">>",
    # Boolean
    "And": "&&", "Or": "||",
}


def _format_op(op: str, args: list) -> str:
    """Render operator with its arguments. Binary ops get infix form."""
    if op in _INFIX_OPS and len(args) == 2:
        return f"({args[0]} {_INFIX_OPS[op]} {args[1]})"
    if op == "Not" and len(args) == 1:
        return f"(! {args[0]})"
    return f"({op} " + " ".join(args) + ")"


def to_smtlib(ast) -> str:
    """Convert a claripy AST to an SMT-LIB2 string.

    Falls back to repr() if claripy's smtlib backend is unavailable.
    """
    try:
        import claripy
        backend = claripy.backends.smtlib_cb
        return backend.convert(ast)
    except Exception:
        try:
            return ast.shallow_repr(max_depth=10)
        except Exception:
            return str(ast)
