# src/ssdf_mcp_query/change_impact_builders.py
"""Pure SQL builders + entity-attr adapters for the change_impact tool
(MEC-1640, task C of MEC-570). No I/O; return (sql, params) like
rule_builders.py, or a pure dict transform.
"""

from __future__ import annotations

from typing import Any

from .rule_builders import build_device_log_coverage_sql  # noqa: F401  (re-exported, reused unchanged)
from .timeparse import parse_time

# Candidate-pull row cap (doc §2.1): ssdf_ro allows up to 1,000,000 result
# rows; this default is deliberately far below that until the lab volume
# measurement in the doc's §2.3 lands, so a first rollout can't accidentally
# pull a row count nobody has load-tested the evaluator against.
DEFAULT_CANDIDATE_LIMIT = 50_000

_LIST_FIELDS = (
    "from_zone",
    "to_zone",
    "source_addresses",
    "dest_addresses",
    "application",
    "service",
    "source_identity",
    "dynamic_application",
    "url_category",
    "source_end_user_profile",
)
_BOOL_FIELDS = (
    "enabled",
    "match_unknown",
    "source_address_excluded",
    "dest_address_excluded",
    "negate_source",
    "negate_destination",
)


def _split_list(value: str | None) -> list[str]:
    if not value:
        return []
    return [v for v in value.split(",") if v]


def policy_entity_to_rule(policy: dict, device_name: str, provider: str) -> dict:
    """Reconstruct a `NormalizedRule`-shaped dict from a configured-policy
    entity's `attrs` (the comma-joined/stringified form `resolve_policies.py`
    writes to `ssdf.entities`). Lossy only in the sense that collector
    rebuilds -- not change_impact -- are the source of truth for new rules; a
    rule name or object-book name containing a literal comma would already
    break `_join`/this adapter identically, so this round-trip is exact for
    every name the collectors themselves can produce.
    """
    attrs = policy.get("attrs", {})
    rule: dict[str, Any] = {
        "provider": provider,
        "device_name": device_name,
        "rule_name": policy.get("name", ""),
        "action": attrs.get("action", ""),
        "position": int(attrs.get("position", 0) or 0),
        "vendor_extras": {},
    }
    for field in _LIST_FIELDS:
        if field in attrs:
            rule[field] = _split_list(attrs.get(field))
    rule.setdefault("from_zone", _split_list(attrs.get("from_zone")))
    rule.setdefault("to_zone", _split_list(attrs.get("to_zone")))
    rule.setdefault("source_addresses", _split_list(attrs.get("source_addresses")))
    rule.setdefault("dest_addresses", _split_list(attrs.get("dest_addresses")))
    rule.setdefault("application", _split_list(attrs.get("application")))
    rule.setdefault("service", _split_list(attrs.get("service")))
    for field in _BOOL_FIELDS:
        rule[field] = attrs.get(field, "false") == "true"
    rule["scheduler_name"] = attrs.get("scheduler_name", "")
    rule["schedule"] = attrs.get("schedule", "")
    if provider == "juniper":
        rule["is_global"] = "any" in rule["from_zone"] and attrs.get("from_zone", "") == "any"
    return rule


def build_latest_object_book_sql(provider: str, device_name: str):
    """Latest resolved object book for one device (task A, MEC-992)."""
    params = {"provider": provider, "device": device_name}
    sql = (
        "SELECT object_book, toString(valid_from) AS valid_from "
        "FROM ssdf.object_book_hash "
        "WHERE provider = {provider:String} AND device_name = {device:String} "
        "ORDER BY valid_from DESC LIMIT 1"
    )
    return sql, params


def build_policy_version_cutoff_sql(device_name: str, rule_names: list[str]):
    """Latest `policy_versions.valid_from` among the named rules on this
    device -- the calibration gate's cutoff (doc §1.4): sessions logged before
    the newest of these rules took effect came from a different rulebase and
    must not be scored against the current one."""
    params = {"device": device_name, "rules": list(rule_names)}
    sql = (
        "SELECT max(valid_from) AS cutoff FROM ssdf.policy_versions "
        "WHERE device_name = {device:String} AND rule_name IN {rules:Array(String)}"
    )
    return sql, params


def build_candidate_pull_sql(
    device_name: str,
    zone_pairs: list[tuple[str, str]],
    since,
    until,
    limit: int = DEFAULT_CANDIDATE_LIMIT,
):
    """Stage-1 candidate pull (doc §2.1): effective tuples for this device,
    restricted to the zone-pairs touched by C, in the window.

    v1 scope note: this filters by device + zone-pair + window only, not the
    full per-rule IP-interval/service pushdown predicate the doc describes
    (`⋃match(C)`) -- that needs the lab volume measurement in doc §2.3 first,
    which has not been run. Filtering at zone-pair granularity is always
    correct (a superset of the true candidate set: the evaluator itself still
    proves every tuple's verdict), just not yet as tight as it can be at
    scale. Flagged for Percy and for a MEC-570 follow-up once `flow_tuples_daily`
    (task B) lands and the real predicate can be pushed down with it.

    A zone of `"any"` (an `any`-zone rule, or a Junos global policy) drops that
    side of the predicate entirely rather than binding the literal string
    `"any"`, since `observer_ingress_zone = 'any'` never matches a real zone
    name and a zone-pair covered only through an `any` rule must still be
    represented in the candidate set.

    The query asks for `limit + 1` rows ordered newest-first: the caller uses
    the extra row to detect truncation and report it, and ordering by
    `timestamp DESC` means a truncated pull favours sessions near the end of
    the window (closest to the proposed change) over the oldest sessions in it.
    """
    since_dt = parse_time(since) if since else parse_time("now-14d")
    until_dt = parse_time(until) if until else parse_time("now")
    params: dict[str, Any] = {
        "device": device_name,
        "since": since_dt.isoformat(),
        "until": until_dt.isoformat(),
    }
    zone_clause = "1=1"
    if zone_pairs:
        pair_clauses = []
        for i, (ingress, egress) in enumerate(zone_pairs):
            side_clauses = []
            if ingress != "any":
                params[f"ingress_{i}"] = ingress
                side_clauses.append(f"observer_ingress_zone = {{ingress_{i}:String}}")
            if egress != "any":
                params[f"egress_{i}"] = egress
                side_clauses.append(f"observer_egress_zone = {{egress_{i}:String}}")
            pair_clauses.append("(" + " AND ".join(side_clauses) + ")" if side_clauses else "1=1")
        zone_clause = "(" + " OR ".join(pair_clauses) + ")"
    sql = (
        "SELECT observer_ingress_zone, observer_egress_zone, source_ip, destination_ip, "
        "network_transport, destination_port, ext, "
        "rule_name, event_action, timestamp "
        "FROM ssdf.events "
        "WHERE observer_hostname = {device:String} "
        "AND timestamp >= parseDateTimeBestEffort({since:String}) "
        "AND timestamp < parseDateTimeBestEffort({until:String}) "
        "AND event_action IN ("
        "'flow_session_close','flow_session_deny','flow_end','flow_deny','flow_drop') "
        f"AND {zone_clause} "
        f"ORDER BY timestamp DESC LIMIT {int(limit) + 1}"
    )
    return sql, params
