"""Compute C, the set of rules that differ between P and P' (doc §1.4), plus
the reordered pairs the config-only pre-check needs.

Identity is `(context, rule_name)`, not `rule_name` alone: Junos policy names
are unique per context, not per device (doc §1.2), so the same name can
legitimately appear in two different zone-pair contexts as two unrelated
rules. A rule that moves from one context to another (e.g. zone-pair ->
global) is therefore a delete-plus-add against its old and new identity, which
matches the doc's "a move counts as delete plus insert."
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .rulemodel import CompiledRule

_IGNORED_FIELDS = {"position"}


@dataclass(frozen=True)
class DiffResult:
    changed_rule_names: set[str] = field(default_factory=set)
    reordered_pairs: list[tuple[str, str]] = field(default_factory=list)
    added: set[str] = field(default_factory=set)
    deleted: set[str] = field(default_factory=set)
    modified: set[str] = field(default_factory=set)
    # Names that identify more than one distinct `(context, name)` rule across
    # P and P' combined: Junos policy names are unique only per context, so a
    # bare-name lookup against these is answering about the wrong rule. The
    # config-only pre-check must fail closed on these.
    ambiguous_names: set[str] = field(default_factory=set)


def _content_equal(a: dict, b: dict) -> bool:
    ak = {k: v for k, v in a.items() if k not in _IGNORED_FIELDS}
    bk = {k: v for k, v in b.items() if k not in _IGNORED_FIELDS}
    return ak == bk


def diff_rulebases(p_rules: list[CompiledRule], pprime_rules: list[CompiledRule]) -> DiffResult:
    p_by_key = {(r.context, r.rule_name): r for r in p_rules}
    pprime_by_key = {(r.context, r.rule_name): r for r in pprime_rules}

    added = {k[1] for k in pprime_by_key if k not in p_by_key}
    deleted = {k[1] for k in p_by_key if k not in pprime_by_key}
    modified = {
        key[1]
        for key in (p_by_key.keys() & pprime_by_key.keys())
        if not _content_equal(p_by_key[key].raw, pprime_by_key[key].raw)
    }

    reordered_pairs: list[tuple[str, str]] = []
    changed_names = set(added) | set(deleted) | set(modified)
    common_contexts: dict = {}
    for key in p_by_key.keys() & pprime_by_key.keys():
        common_contexts.setdefault(key[0], []).append(key[1])

    for context, names in common_contexts.items():
        for i, name_a in enumerate(names):
            for name_b in names[i + 1 :]:
                pos_a_p = p_by_key[(context, name_a)].position
                pos_b_p = p_by_key[(context, name_b)].position
                pos_a_q = pprime_by_key[(context, name_a)].position
                pos_b_q = pprime_by_key[(context, name_b)].position
                order_before = pos_a_p < pos_b_p
                order_after = pos_a_q < pos_b_q
                if order_before != order_after:
                    reordered_pairs.append((name_a, name_b))
                    changed_names.add(name_a)
                    changed_names.add(name_b)

    contexts_by_name: dict[str, set] = {}
    for key in set(p_by_key) | set(pprime_by_key):
        contexts_by_name.setdefault(key[1], set()).add(key[0])
    ambiguous_names = {name for name, contexts in contexts_by_name.items() if len(contexts) > 1}

    return DiffResult(
        changed_rule_names=changed_names,
        reordered_pairs=reordered_pairs,
        added=added,
        deleted=deleted,
        modified=modified,
        ambiguous_names=ambiguous_names,
    )
