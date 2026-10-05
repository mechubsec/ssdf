"""Strong Kleene three-valued logic: match / no_match / unknown.

This is the formalism behind every match-clause test in the evaluator (§1.2 of
the change-impact-scope doc): a clause is never "probably" true. It is
`K_TRUE`, `K_FALSE`, or `K_UNKNOWN`, and clauses combine with Kleene AND/OR/NOT
so that a definite `K_FALSE` always dominates an unresolved clause elsewhere in
the same rule -- a rule that fails on a *known* field is still provably
`no_match`, even if it also carries one unrelated clause this tool can't
resolve (e.g. a PAN-OS HIP profile). Only when no clause is definitely false,
and at least one is unresolved, is the overall result `K_UNKNOWN`.
"""

from __future__ import annotations

from enum import Enum


class Kleene3(Enum):
    FALSE = "no_match"
    TRUE = "match"
    UNKNOWN = "unknown"


K_FALSE = Kleene3.FALSE
K_TRUE = Kleene3.TRUE
K_UNKNOWN = Kleene3.UNKNOWN


def k_and(*values: Kleene3) -> Kleene3:
    """Strong Kleene AND: FALSE dominates, then UNKNOWN, else TRUE."""
    if not values:
        return K_TRUE
    if any(v is K_FALSE for v in values):
        return K_FALSE
    if any(v is K_UNKNOWN for v in values):
        return K_UNKNOWN
    return K_TRUE


def k_or(*values: Kleene3) -> Kleene3:
    """Strong Kleene OR: TRUE dominates, then UNKNOWN, else FALSE."""
    if not values:
        return K_FALSE
    if any(v is K_TRUE for v in values):
        return K_TRUE
    if any(v is K_UNKNOWN for v in values):
        return K_UNKNOWN
    return K_FALSE


def k_not(value: Kleene3) -> Kleene3:
    if value is K_TRUE:
        return K_FALSE
    if value is K_FALSE:
        return K_TRUE
    return K_UNKNOWN
