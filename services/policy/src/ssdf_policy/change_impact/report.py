"""Output / honesty contract (doc §1.6) -- the part Percy reviews hardest.

Every number in a report is query/evaluator output; the only prose this
module writes is deterministic string formatting over those cited numbers,
the same `explain_rule` depth as the rest of the rule-memory tool surface. The
words "safe" and "no impact" never appear anywhere in this module's output.
The only zero-result wording is `NO_SESSIONS_OBSERVED`, or
`CONFIG_ONLY_NO_IMPACT` when the §1.4 pre-check proves it without looking at
traffic. A deny-widening count with no logged denies is always the string
`"unknown"`, never `0` -- deny-side blindness (doc §6) must never read as
"nothing happened".
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .calibration import CalibrationResult
from .evaluator import Classification, EvaluatedTuple

TOP_N_DEFAULT = 10

NO_SESSIONS_OBSERVED = "no historical sessions observed in the analysable scope"
CONFIG_ONLY_NO_IMPACT = "provably no impact (config-only)"


def content_hash(payload: Any) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()


def _tuple_summary(item: EvaluatedTuple) -> dict:
    return {
        "src_ip": item.flow.src_ip,
        "dst_ip": item.flow.dst_ip,
        "transport": item.flow.transport,
        "dst_port": item.flow.dst_port,
        "ingress_zone": item.flow.ingress_zone,
        "egress_zone": item.flow.egress_zone,
        "sessions": item.sessions,
        "bytes": item.bytes_,
        "first_seen": item.first_seen,
        "last_seen": item.last_seen,
        "logged_rules": list(item.logged_rules),
    }


def _class_key(item: EvaluatedTuple) -> str:
    if item.classification == Classification.VERDICT_CHANGE:
        return f"verdict_change_{item.direction}"
    return item.classification.value


def _bucket_by_class(items: list[EvaluatedTuple], top_n: int) -> dict:
    buckets: dict[str, list[EvaluatedTuple]] = {}
    for item in items:
        buckets.setdefault(_class_key(item), []).append(item)
    out = {}
    for key, bucket in buckets.items():
        top = sorted(bucket, key=lambda i: i.sessions, reverse=True)[:top_n]
        out[key] = {
            "distinct_tuples": len(bucket),
            "sessions": sum(i.sessions for i in bucket),
            "bytes": sum(i.bytes_ for i in bucket),
            "top_tuples": [_tuple_summary(i) for i in top],
        }
    return out


def _rule_relevant(rule_name: str, item: EvaluatedTuple) -> bool:
    return (
        rule_name in item.logged_rules
        or item.before.rule_name == rule_name
        or item.after.rule_name == rule_name
    )


def build_rule_section(
    rule_name: str,
    evaluated: list[EvaluatedTuple],
    *,
    config_only: bool = False,
    top_n: int = TOP_N_DEFAULT,
    truncated_at: int | None = None,
) -> dict:
    if config_only:
        return {"rule_name": rule_name, "result": CONFIG_ONLY_NO_IMPACT}
    relevant = [item for item in evaluated if _rule_relevant(rule_name, item)]
    if not relevant:
        if truncated_at is not None:
            # The candidate pull was cut off before the window closed (MEC-1644
            # F2): "no sessions observed" would read as evidence this rule saw
            # no traffic, when it's really an artefact of the row cap. Say so.
            return {
                "rule_name": rule_name,
                "result": f"unknown: candidate pull truncated at {truncated_at} rows",
            }
        return {"rule_name": rule_name, "result": NO_SESSIONS_OBSERVED}
    return {
        "rule_name": rule_name,
        "result": None,
        "classes": _bucket_by_class(relevant, top_n),
    }


def build_deny_side_blindness(
    evaluated: list[EvaluatedTuple], deny_logging_observed: dict[tuple[str, str], bool]
) -> dict:
    """For every zone-pair that has an "opens" (deny->allow) count, pair it
    with whether that zone-pair had ANY logged deny in the window. If not,
    the count is reported as the literal string "unknown" -- never 0 --
    because a rule that never logged a deny can't prove its traffic was zero;
    it proves only that nobody turned deny logging on (doc §6)."""
    by_zone: dict[tuple[str, str], list[EvaluatedTuple]] = {}
    for item in evaluated:
        if item.classification == Classification.VERDICT_CHANGE and item.direction == "opens":
            zp = (item.flow.ingress_zone, item.flow.egress_zone)
            by_zone.setdefault(zp, []).append(item)

    out = {}
    for zp, items in by_zone.items():
        deny_logged = deny_logging_observed.get(zp, False)
        sessions = sum(i.sessions for i in items)
        out["->".join(zp)] = {
            "deny_logging_observed": deny_logged,
            "newly_allowed_sessions": sessions if deny_logged else "unknown",
            "note": (
                "deny-side logging was observed in-window for this zone-pair"
                if deny_logged
                else (
                    "no deny was logged in-window for this zone-pair; a widened rule's "
                    "newly-allowed traffic cannot be counted and is reported as unknown, "
                    "not zero"
                )
            ),
        }
    return out


def build_calibration_section(calibration: dict[tuple[str, str], CalibrationResult]) -> dict:
    out = {}
    for zp, result in calibration.items():
        entry = {
            "agreement": result.agreement,
            "sample_sessions": result.sample_sessions,
            "threshold": result.threshold,
            "min_sample": result.min_sample,
            "status": result.status,
        }
        if result.status != "ok":
            entry["downgrade_reason"] = "unknown: model does not reproduce device behaviour"
            entry["mismatch_examples"] = list(result.mismatch_examples)
        out["->".join(zp)] = entry
    return out


def build_report(
    *,
    device_name: str,
    window_since: str,
    window_until: str,
    p_rules: list[dict],
    pprime_rules: list[dict],
    delta_payload: Any,
    rule_sections: list[dict],
    calibration: dict[tuple[str, str], CalibrationResult],
    deny_side_blindness: dict,
    coverage: dict,
    truncated: bool = False,
) -> dict:
    """Assemble the final change_impact report. `rule_sections` is a list of
    `build_rule_section(...)` outputs, one per rule in C, aggregate + per-rule.
    """
    return {
        "device_name": device_name,
        "window": {
            "since": window_since,
            "until": window_until,
            "note": "flows with a period longer than the window are not represented",
        },
        "hashes": {
            "p": content_hash(p_rules),
            "pprime": content_hash(pprime_rules),
            "delta": content_hash(delta_payload),
        },
        "changed_rules": rule_sections,
        "calibration": build_calibration_section(calibration),
        "deny_side_blindness": deny_side_blindness,
        "coverage": coverage,
        "truncated": truncated,
    }
