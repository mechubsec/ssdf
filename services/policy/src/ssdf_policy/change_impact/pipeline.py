"""Top-level orchestration: glue delta application, diffing, the config-only
pre-check, candidate evaluation, the calibration gate, and report assembly
into one pure call. No ClickHouse or device I/O -- `candidates` is already
the stage-1 SQL pull (doc §2.1), and `deny_logging_observed` /
`cutoff_by_zone_pair` / `coverage` are already-computed inputs from the
caller (the MCP tool wrapper in services/mcp-query owns that I/O).
"""

from __future__ import annotations

from typing import Any

from .calibration import apply_calibration_gate, calibration_gate
from .diff import diff_rulebases
from .evaluator import config_only_precheck, evaluate_candidates
from .flowtuple import effective_tuple
from .report import build_deny_side_blindness, build_report, build_rule_section
from .rulemodel import compile_rulebase


def evaluate_change_impact(
    *,
    device_name: str,
    provider: str,
    p_rules: list[dict],
    pprime_rules: list[dict],
    object_book: dict,
    candidates: list[dict],
    window_since: str,
    window_until: str,
    delta_payload: Any,
    cutoff_by_zone_pair: dict[tuple[str, str], str] | None = None,
    deny_logging_observed: dict[tuple[str, str], bool] | None = None,
    coverage: dict | None = None,
    calibration_threshold: float = 0.99,
    calibration_min_sample: int = 100,
    truncated: bool = False,
) -> dict:
    """`candidates` rows are the stage-1 pull: each a dict with `tuple` (a raw
    event-row dict suitable for `effective_tuple`, or already a `FlowTuple`),
    `sessions`, `bytes`, `first_seen`, `last_seen`, `logged_rules`.
    """
    p_compiled = compile_rulebase(p_rules, object_book)
    pprime_compiled = compile_rulebase(pprime_rules, object_book)

    diff_result = diff_rulebases(p_compiled, pprime_compiled)

    p_by_name = {r.rule_name: r for r in p_compiled}
    pprime_by_name = {r.rule_name: r for r in pprime_compiled}

    config_only = config_only_precheck(
        diff_result.changed_rule_names,
        p_by_name,
        pprime_by_name,
        reordered_pairs=diff_result.reordered_pairs,
    )

    rule_sections = []
    if config_only is not None:
        for name in sorted(diff_result.changed_rule_names):
            rule_sections.append(build_rule_section(name, [], config_only=True))
        return build_report(
            device_name=device_name,
            window_since=window_since,
            window_until=window_until,
            p_rules=p_rules,
            pprime_rules=pprime_rules,
            delta_payload=delta_payload,
            rule_sections=rule_sections,
            calibration={},
            deny_side_blindness={},
            coverage=coverage or {},
            truncated=truncated,
        )

    normalized_candidates = []
    for row in candidates:
        tup = row["tuple"]
        if not hasattr(tup, "ingress_zone"):
            tup = effective_tuple(tup, provider)
        normalized_candidates.append({**row, "tuple": tup})

    evaluated = evaluate_candidates(normalized_candidates, p_compiled, pprime_compiled, provider)

    calibration = calibration_gate(
        evaluated,
        cutoff_by_zone_pair=cutoff_by_zone_pair,
        threshold=calibration_threshold,
        min_sample=calibration_min_sample,
    )
    evaluated = apply_calibration_gate(evaluated, calibration)

    for name in sorted(diff_result.changed_rule_names):
        rule_sections.append(build_rule_section(name, evaluated))

    deny_side_blindness = build_deny_side_blindness(evaluated, deny_logging_observed or {})

    return build_report(
        device_name=device_name,
        window_since=window_since,
        window_until=window_until,
        p_rules=p_rules,
        pprime_rules=pprime_rules,
        delta_payload=delta_payload,
        rule_sections=rule_sections,
        calibration=calibration,
        deny_side_blindness=deny_side_blindness,
        coverage=coverage or {},
        truncated=truncated,
    )
