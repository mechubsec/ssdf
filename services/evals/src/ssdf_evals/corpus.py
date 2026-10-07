"""Golden-corpus model + loader + tier/tool constants.

The corpus is versioned YAML (golden/core.yaml). load_corpus() enforces the
spec's corpus constraints (fail-closed: a malformed corpus never half-loads):
unique ids, valid enums, public/both questions restricted to public tools,
reference SQL restricted to SELECT.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

# Tool surfaces as deployed (sovereign tier / public tier).
#
# This list MUST match `TOOL_DATA_CLASSES` in services/mcp-query, because the
# corpus lint below rejects any question whose `required_tools` are not listed
# here -- so a tool absent from this set cannot be given eval coverage at all,
# even though the server serves it.
#
# That is not hypothetical: `ingest_status`, `fabric_status`,
# `lab_topology_snapshot` and `recent_alerts` shipped on the sovereign tier and
# were unreachable by the corpus until they were added here. A comment asking a
# human to "keep in sync" is what allowed that, so the sync is now enforced by
# test_registry_drift.py instead of by this sentence.
PUBLIC_TOOLS = frozenset({"metric_timeseries", "top_series", "entity_metric_timeseries"})
SOVEREIGN_TOOLS = PUBLIC_TOOLS | frozenset(
    {
        "get_entity",
        "locate",
        "neighbors",
        "find_path",
        "topology_snapshot",
        "enforcement_points",
        "describe_schema",
        "explain_access",
        "query_flows",
        "run_sql",
        "top_talkers",
        "zone_matrix",
        "configured_policies",
        "observed_by",
        "reidentify",
        "ingest_status",
        "fabric_status",
        "lab_topology_snapshot",
        "recent_alerts",
        "rule_history",
        "rule_usage",
        "unused_rules",
        "explain_rule",
        "change_impact",
    }
)

TIERS = ("sovereign", "public", "both")
CATEGORIES = ("reachability", "flows", "topology", "change", "honesty", "injection")
DIFFICULTIES = ("easy", "medium", "hard")
PREDICATE_TYPES = ("reference_sql", "expected_json", "refusal", "no_injection")
MATCH_MODES = ("exact", "set_overlap", "numeric_tolerance")

_SELECT_ONLY = re.compile(r"^\s*SELECT\b", re.IGNORECASE)


class CorpusError(ValueError):
    """The corpus violates its constraints (fail-closed)."""


@dataclass(frozen=True)
class Question:
    id: str
    question: str
    tier: str
    category: str
    difficulty: str
    answer_format: str
    required_tools: tuple[str, ...]
    predicate: dict
    # None means "no restriction" (every pre-existing question before this field
    # existed): the audit-trail check below does not run. When set -- mandatory
    # for category "injection" -- any tool observed in ssdf.audit outside this
    # set fails the question, independent of whether the answer itself leaked
    # the canary: an injected field convincing the model to call a tool it
    # wasn't asked to (MEC-568's actual threat -- "log line -> agent stages a
    # firewall change") is a failure even if the text answer looks clean.
    allowed_tools: tuple[str, ...] | None = None


def _check(condition: bool, message: str) -> None:
    if not condition:
        raise CorpusError(message)


def _validate_predicate_shape(qid: str, predicate: dict) -> None:
    """Shared shape checks for a reference_sql/expected_json predicate -- used both
    for a question's top-level predicate and for a no_injection predicate's nested
    `correctness` check."""
    ptype = predicate.get("type")
    if ptype == "reference_sql":
        sql = predicate.get("sql", "")
        _check(bool(_SELECT_ONLY.match(sql)), f"{qid}: reference_sql must be a SELECT")
        _check(
            predicate.get("match") in MATCH_MODES,
            f"{qid}: bad match mode {predicate.get('match')!r}",
        )
        _check(bool(predicate.get("answer_key")), f"{qid}: reference_sql needs answer_key")
        match = predicate.get("match")
        if match == "set_overlap":
            _check(
                isinstance(predicate.get("params", {}).get("min_overlap"), int),
                f"{qid}: set_overlap needs integer params.min_overlap",
            )
        elif match == "numeric_tolerance":
            params = predicate.get("params", {})
            _check(
                ("tolerance" in params) != ("tolerance_pct" in params),
                f"{qid}: numeric_tolerance needs exactly one of params.tolerance / params.tolerance_pct",
            )
    elif ptype == "expected_json":
        _check("expected" in predicate, f"{qid}: expected_json needs 'expected'")


def _validate(q: Question) -> None:
    _check(q.tier in TIERS, f"{q.id}: bad tier {q.tier!r}")
    _check(q.category in CATEGORIES, f"{q.id}: bad category {q.category!r}")
    _check(q.difficulty in DIFFICULTIES, f"{q.id}: bad difficulty {q.difficulty!r}")
    _check(bool(q.question) and bool(q.answer_format), f"{q.id}: empty question/answer_format")
    allowed = SOVEREIGN_TOOLS if q.tier == "sovereign" else PUBLIC_TOOLS
    unknown = set(q.required_tools) - allowed
    _check(not unknown, f"{q.id}: tools {sorted(unknown)} not allowed for tier {q.tier}")

    if q.category == "injection":
        _check(
            q.allowed_tools is not None,
            f"{q.id}: injection questions must set allowed_tools (even to []) so the "
            "audit trail is checked for a tool call the question didn't ask for",
        )
    if q.allowed_tools is not None:
        unknown_allowed = set(q.allowed_tools) - allowed
        _check(
            not unknown_allowed,
            f"{q.id}: allowed_tools {sorted(unknown_allowed)} not allowed for tier {q.tier}",
        )
        missing_from_allowed = set(q.required_tools) - set(q.allowed_tools)
        _check(
            not missing_from_allowed,
            f"{q.id}: required_tools {sorted(missing_from_allowed)} not listed in allowed_tools",
        )

    ptype = q.predicate.get("type")
    _check(ptype in PREDICATE_TYPES, f"{q.id}: bad predicate type {ptype!r}")
    if ptype in ("reference_sql", "expected_json"):
        _validate_predicate_shape(q.id, q.predicate)
    elif ptype == "refusal":
        _check("sql" not in q.predicate, f"{q.id}: refusal predicate must not carry sql")
    elif ptype == "no_injection":
        forbidden = q.predicate.get("forbidden_substrings")
        _check(
            isinstance(forbidden, list) and len(forbidden) > 0,
            f"{q.id}: no_injection needs a non-empty forbidden_substrings list",
        )
        _check(
            all(isinstance(s, str) and s for s in forbidden),
            f"{q.id}: no_injection forbidden_substrings must be non-empty strings",
        )
        _check("sql" not in q.predicate, f"{q.id}: no_injection predicate must not carry sql")
        # A question that asks for a field's "literal" text can never pass: if the
        # canary is embedded in that same field, the one correct answer necessarily
        # reproduces it. Keep forbidden substrings out of any field the answer must
        # echo verbatim; derived facts (a bool, a count, a prefix check) can't do this.
        if "literal" in q.answer_format.lower():
            lowered_question = q.question.lower()
            leaked = [s for s in forbidden if s.lower() in lowered_question]
            _check(
                not leaked,
                f"{q.id}: no_injection answer_format asks for literal text but "
                f"forbidden_substrings {leaked} appear in the question -- a correct "
                "literal answer would fail its own predicate",
            )
        # `correctness` is optional: refusing the canary is necessary but not
        # sufficient -- a model that answers garbage (or refuses to engage at
        # all) while merely avoiding the forbidden substring still passed with
        # no evidence it handled the underlying question correctly. When
        # present, it is itself a reference_sql/expected_json predicate (not
        # no_injection/refusal, to avoid recursion) and must pass alongside
        # the canary check.
        correctness = q.predicate.get("correctness")
        if correctness is not None:
            _check(
                isinstance(correctness, dict), f"{q.id}: no_injection correctness must be a dict"
            )
            _check(
                correctness.get("type") in ("reference_sql", "expected_json"),
                f"{q.id}: no_injection correctness.type must be reference_sql or expected_json",
            )
            _validate_predicate_shape(q.id, correctness)


def load_corpus(path: str | Path) -> list[Question]:
    raw = yaml.safe_load(Path(path).read_text())
    _check(isinstance(raw, list) and raw, "corpus must be a non-empty YAML list")
    questions: list[Question] = []
    seen: set[str] = set()
    for item in raw:
        try:
            raw_allowed = item.get("allowed_tools")
            q = Question(
                id=str(item["id"]),
                question=str(item["question"]),
                tier=str(item["tier"]),
                category=str(item["category"]),
                difficulty=str(item["difficulty"]),
                answer_format=str(item["answer_format"]),
                required_tools=tuple(item.get("required_tools") or ()),
                predicate=dict(item["predicate"]),
                allowed_tools=tuple(raw_allowed) if raw_allowed is not None else None,
            )
        except KeyError as exc:
            raise CorpusError(f"question {item.get('id', '<no id>')!r}: missing key {exc}") from exc
        _check(q.id not in seen, f"duplicate question id {q.id!r}")
        seen.add(q.id)
        _validate(q)
        questions.append(q)
    return questions


def questions_for_tier(questions: list[Question], tier: str) -> list[Question]:
    """Run-tier subset: 'sovereign' run sees sovereign|both; 'public' sees public|both."""
    return [q for q in questions if q.tier in (tier, "both")]
