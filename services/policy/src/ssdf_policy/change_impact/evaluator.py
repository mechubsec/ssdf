"""Differential first-match replay (doc §1.4): firstmatch3, classification,
and the config-only candidate-pruning pre-check.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable

from .flowtuple import FlowTuple
from .kleene import K_FALSE, K_TRUE, K_UNKNOWN
from .rulemodel import CompiledRule

ALLOW = "allow"


@dataclass(frozen=True)
class Verdict:
    """The outcome of one firstmatch3 walk."""

    rule_name: str | None  # None => default-deny
    action: str | None  # None when status == "unknown" and no eventual match was found
    status: str  # "match" | "unknown"
    unknown_from: str | None = None
    unknown_until: str | None = None  # None => "never confirmed, ran off the end of the rulebase"


def _junos_context_order(rules_by_context: dict, flow: FlowTuple) -> list[list[CompiledRule]]:
    zonepair_key = ("zonepair", (flow.ingress_zone,), (flow.egress_zone,))
    # A zone-pair context's from_zone/to_zone lists may carry more than the
    # single flow-relevant pair if `match from-zone/to-zone` was repeated
    # under a from-zone/to-zone header -- include any context whose zone
    # lists contain the flow's zones (or "any"), not only the exact
    # single-element match, without ever comparing `position` across them.
    zonepair_contexts = [
        ctx
        for ctx in rules_by_context
        if ctx[0] == "zonepair"
        and ("any" in ctx[1] or flow.ingress_zone in ctx[1])
        and ("any" in ctx[2] or flow.egress_zone in ctx[2])
    ]
    # Exact match first (most specific), then broader multi-zone contexts, in
    # a stable order so repeated evaluations of the same rulebase are
    # deterministic.
    zonepair_contexts.sort(key=lambda c: (c != zonepair_key, c))
    global_contexts = [ctx for ctx in rules_by_context if ctx[0] == "global"]
    ordered: list[list[CompiledRule]] = []
    for ctx in zonepair_contexts + global_contexts:
        ordered.append(sorted(rules_by_context[ctx], key=lambda r: r.position))
    return ordered


def _group_by_context(rules: Iterable[CompiledRule]) -> dict:
    grouped: dict = {}
    for rule in rules:
        grouped.setdefault(rule.context, []).append(rule)
    return grouped


def _default_action(provider: str, flow: FlowTuple) -> str:
    if provider == "paloalto" and flow.ingress_zone and flow.ingress_zone == flow.egress_zone:
        return ALLOW  # intrazone-default
    return "deny"  # Junos default policy / PAN-OS interzone-default


def firstmatch3(rules: list[CompiledRule], flow: FlowTuple, provider: str) -> Verdict:
    """Walk the vendor's context order (doc §1.2) and return the first-match
    verdict, three-valued. Disabled rules never match in either rulebase."""
    if provider == "juniper":
        contexts = _junos_context_order(_group_by_context(rules), flow)
    elif provider == "paloalto":
        contexts = [sorted((r for r in rules if r.context == ("panos",)), key=lambda r: r.position)]
    else:
        raise ValueError(f"unsupported provider: {provider!r}")

    first_unknown: str | None = None
    for context_rules in contexts:
        for rule in context_rules:
            if not rule.enabled:
                continue
            result = rule.match(flow)
            if result is K_FALSE:
                continue
            if result is K_TRUE:
                if first_unknown is None:
                    return Verdict(rule_name=rule.rule_name, action=rule.action, status="match")
                return Verdict(
                    rule_name=None,
                    action=None,
                    status="unknown",
                    unknown_from=first_unknown,
                    unknown_until=rule.rule_name,
                )
            assert result is K_UNKNOWN
            if first_unknown is None:
                first_unknown = rule.rule_name

    if first_unknown is not None:
        return Verdict(
            rule_name=None,
            action=None,
            status="unknown",
            unknown_from=first_unknown,
            unknown_until=None,
        )
    return Verdict(rule_name=None, action=_default_action(provider, flow), status="match")


class Classification(str, Enum):
    UNCHANGED = "unchanged"
    RULE_SHIFT = "rule_shift"
    VERDICT_CHANGE = "verdict_change"
    INDETERMINATE = "indeterminate"


@dataclass(frozen=True)
class EvaluatedTuple:
    flow: FlowTuple
    before: Verdict
    after: Verdict
    classification: Classification
    direction: str | None  # "opens" | "breaks" | None
    sessions: int = 0
    bytes_: int = 0
    first_seen: str | None = None
    last_seen: str | None = None
    logged_rules: tuple[str, ...] = field(default_factory=tuple)


def classify(before: Verdict, after: Verdict) -> tuple[Classification, str | None]:
    if before.status == "unknown" or after.status == "unknown":
        return Classification.INDETERMINATE, None
    before_allow = before.action == ALLOW
    after_allow = after.action == ALLOW
    if before.action == after.action and before.rule_name == after.rule_name:
        return Classification.UNCHANGED, None
    if before.action == after.action:
        return Classification.RULE_SHIFT, None
    direction = "opens" if (not before_allow and after_allow) else "breaks"
    return Classification.VERDICT_CHANGE, direction


def _match_sets_disjoint(a: CompiledRule, b: CompiledRule) -> bool:
    """Sound but incomplete: proves disjointness only via zone non-overlap.
    Never returns True for rules that could actually overlap -- a false
    "not disjoint" just falls through to full candidate evaluation, which is
    always safe; a false "disjoint" would not be."""
    a_from = set(a.raw.get("from_zone") or ["any"])
    a_to = set(a.raw.get("to_zone") or ["any"])
    b_from = set(b.raw.get("from_zone") or ["any"])
    b_to = set(b.raw.get("to_zone") or ["any"])
    if "any" in a_from or "any" in b_from or "any" in a_to or "any" in b_to:
        return False
    return a_from.isdisjoint(b_from) or a_to.isdisjoint(b_to)


def _disabled_in_both(
    name: str,
    p_by_name: dict[str, CompiledRule],
    pprime_by_name: dict[str, CompiledRule],
) -> bool:
    before = p_by_name.get(name)
    after = pprime_by_name.get(name)
    before_disabled = before is None or not before.enabled
    after_disabled = after is None or not after.enabled
    return before_disabled and after_disabled


def config_only_precheck(
    changed_rule_names: set[str],
    p_by_name: dict[str, CompiledRule],
    pprime_by_name: dict[str, CompiledRule],
    reordered_pairs: list[tuple[str, str]] | None = None,
    content_changed_names: set[str] | None = None,
    ambiguous_names: set[str] | None = None,
) -> str | None:
    """Return the doc §1.4 "provably no impact (config-only)" wording if either
    config-only condition holds, else None (meaning: must evaluate candidates
    against traffic data).

    Every name in `changed_rule_names` must be individually accounted for
    before a config-only verdict is returned: either it is disabled in both
    P and P' (content-changed names, via `content_changed_names`), or it is
    one half of a pure reorder pair -- unchanged in content, only moved --
    whose pairwise same-action/disjoint check proves the reorder is
    equivalence-preserving. A name that is part of a `reordered_pairs` entry
    but also changed content does not qualify as a pure reorder and falls
    back to the content-changed requirement.

    `ambiguous_names` are names that resolve to more than one `(context,
    name)` rule across P/P'; `p_by_name`/`pprime_by_name` can only ever hold
    one rule per bare name, so these are refused up front rather than
    answering about the wrong rule.
    """
    if not changed_rule_names:
        return None

    ambiguous_names = ambiguous_names or set()
    if changed_rule_names & ambiguous_names:
        return None

    content_changed_names = (
        content_changed_names if content_changed_names is not None else changed_rule_names
    )
    if not all(
        _disabled_in_both(name, p_by_name, pprime_by_name) for name in content_changed_names
    ):
        return None

    reordered_pairs = reordered_pairs or []
    pure_reorder_pairs = [
        (name_a, name_b)
        for name_a, name_b in reordered_pairs
        if name_a not in content_changed_names and name_b not in content_changed_names
    ]

    accounted_names = set(content_changed_names)
    for name_a, name_b in pure_reorder_pairs:
        accounted_names.add(name_a)
        accounted_names.add(name_b)
        rule_a = pprime_by_name.get(name_a) or p_by_name.get(name_a)
        rule_b = pprime_by_name.get(name_b) or p_by_name.get(name_b)
        if rule_a is None or rule_b is None:
            return None
        same_action = rule_a.action == rule_b.action
        if not (same_action or _match_sets_disjoint(rule_a, rule_b)):
            return None

    if changed_rule_names - accounted_names:
        # Defence in depth: every changed name must be accounted for by
        # either the content-changed check above or a pure reorder pair.
        return None

    return "provably no impact (config-only)"


def evaluate_candidates(
    candidates: list[dict],
    p_rules: list[CompiledRule],
    pprime_rules: list[CompiledRule],
    provider: str,
) -> list[EvaluatedTuple]:
    """Run firstmatch3 against P and P' for each pre-pulled candidate row and
    classify the result. `candidates` rows already carry an `effective_tuple`
    (a `FlowTuple`) plus aggregate fields from stage 1 -- this function does
    no ClickHouse I/O.
    """
    results = []
    for row in candidates:
        flow: FlowTuple = row["tuple"]
        before = firstmatch3(p_rules, flow, provider)
        after = firstmatch3(pprime_rules, flow, provider)
        classification, direction = classify(before, after)
        results.append(
            EvaluatedTuple(
                flow=flow,
                before=before,
                after=after,
                classification=classification,
                direction=direction,
                sessions=int(row.get("sessions", 0)),
                bytes_=int(row.get("bytes", 0)),
                first_seen=row.get("first_seen"),
                last_seen=row.get("last_seen"),
                logged_rules=tuple(row.get("logged_rules") or ()),
            )
        )
    return results
