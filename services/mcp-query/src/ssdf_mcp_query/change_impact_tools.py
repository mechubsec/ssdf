"""change_impact MCP tool (MEC-1640, task C of MEC-570): read-only differential
first-match replay. No write capability, no `--allow-direct-commit` gate --
this tool never issues a device command, only reads ssdf.entities/events and
runs the pure evaluator in `ssdf_policy.change_impact`.

Every call here reaches ssdf.audit through server.py's `audited_tool` wrapper
like `rule_tools.py`'s tools do -- see that module's docstring for why that is
the MEC-565 evidence-tier join this feature needs.
"""

from __future__ import annotations

import json

from ssdf_policy.change_impact import evaluate_change_impact
from ssdf_policy.change_impact.delta import (
    apply_delta,
    apply_junos_text_delta,
    parse_json_delta,
)

from .change_impact_builders import (
    build_candidate_pull_sql,
    build_latest_object_book_sql,
    build_policy_version_cutoff_sql,
    policy_entity_to_rule,
)
from .timeparse import parse_time

DEFAULT_WINDOW_DAYS = 14  # doc §4: raw-events default until flow_tuples_daily (task B) lands


class ChangeImpactError(ValueError):
    pass


def _aggregate_candidates(rows: list[dict]) -> list[dict]:
    """Group raw `ssdf.events` rows into effective-tuple candidates (doc §1.3).

    v1 does this in Python rather than pushing the NAT-aware GROUP BY into
    ClickHouse (see change_impact_builders.build_candidate_pull_sql docstring)
    -- correct, not yet the scale-optimized form doc §2.1 describes.
    """
    from ssdf_policy.change_impact.flowtuple import effective_tuple

    buckets: dict[tuple, dict] = {}
    for row in rows:
        tup = effective_tuple(row, row.get("provider", "juniper"))
        key = (
            tup.ingress_zone,
            tup.egress_zone,
            tup.src_ip,
            tup.dst_ip,
            tup.transport,
            tup.dst_port,
            tup.app,
        )
        bucket = buckets.get(key)
        if bucket is None:
            bucket = {
                "tuple": tup,
                "sessions": 0,
                "bytes": 0,
                "first_seen": row.get("timestamp"),
                "last_seen": row.get("timestamp"),
                "logged_rules": set(),
            }
            buckets[key] = bucket
        bucket["sessions"] += 1
        bucket["bytes"] += int(row.get("bytes", 0) or 0)
        ts = row.get("timestamp")
        if ts is not None:
            if bucket["first_seen"] is None or ts < bucket["first_seen"]:
                bucket["first_seen"] = ts
            if bucket["last_seen"] is None or ts > bucket["last_seen"]:
                bucket["last_seen"] = ts
        rule_name = row.get("rule_name")
        if rule_name:
            bucket["logged_rules"].add(rule_name)
    out = []
    for bucket in buckets.values():
        bucket["logged_rules"] = sorted(bucket["logged_rules"])
        out.append(bucket)
    return out


class ChangeImpactTools:
    """Stateless change_impact tool surface bound to a ClickHouse client +
    EntityStore, mirroring `RuleTools`'s construction (rule_tools.py)."""

    def __init__(self, ch_client, entity_store):
        self._ch = ch_client
        self._store = entity_store

    def _configured_rules(self, device_name: str, provider: str) -> list[dict]:
        items = self._store.configured_policies_for_firewalls([device_name])
        return [policy_entity_to_rule(item["policy"], device_name, provider) for item in items]

    def _object_book(self, provider: str, device_name: str) -> dict:
        sql, params = build_latest_object_book_sql(provider, device_name)
        rows = self._ch.run(sql, params)["rows"]
        if not rows:
            return {}
        return json.loads(rows[0]["object_book"])

    def _zone_pairs(self, rules: list[dict]) -> list[tuple[str, str]]:
        pairs = set()
        for rule in rules:
            for fz in rule.get("from_zone") or ["any"]:
                for tz in rule.get("to_zone") or ["any"]:
                    pairs.add((fz, tz))
        return sorted(pairs)

    def change_impact(
        self,
        device_name: str,
        provider: str,
        delta: dict | list,
        junos_current_text: str | None = None,
        since: str | None = None,
        until: str | None = None,
        deny_logging_observed: dict | None = None,
    ) -> dict:
        """`delta` is either the vendor-neutral JSON op list (a list of op
        dicts) or, for Junos text form, a dict `{"lines": [...]}` -- requires
        `junos_current_text` (the device's current `| display set` output)
        since that form diffs text, not the stored rule list.
        """
        since = since or f"now-{DEFAULT_WINDOW_DAYS}d"
        until = until or "now"
        since_iso = parse_time(since).isoformat()
        until_iso = parse_time(until).isoformat()

        if provider == "juniper" and isinstance(delta, dict) and "lines" in delta:
            if not junos_current_text:
                raise ChangeImpactError("junos text delta requires junos_current_text")
            p_rules, pprime_rules = apply_junos_text_delta(
                junos_current_text, delta["lines"], device_name, until_iso
            )
            delta_payload = delta
        elif isinstance(delta, list):
            p_rules = self._configured_rules(device_name, provider)
            delta_obj = parse_json_delta(delta)
            pprime_rules = apply_delta(p_rules, delta_obj)
            delta_payload = delta
        else:
            raise ChangeImpactError(
                "delta must be a JSON op list, or {'lines': [...]} for the Junos text form"
            )

        object_book = self._object_book(provider, device_name)
        all_names = sorted(
            {r["rule_name"] for r in p_rules} | {r["rule_name"] for r in pprime_rules}
        )
        cutoff_sql, cutoff_params = build_policy_version_cutoff_sql(device_name, all_names)
        cutoff_rows = self._ch.run(cutoff_sql, cutoff_params)["rows"]
        cutoff = cutoff_rows[0]["cutoff"] if cutoff_rows and cutoff_rows[0].get("cutoff") else None

        zone_pairs = self._zone_pairs(p_rules) + self._zone_pairs(pprime_rules)
        candidate_sql, candidate_params = build_candidate_pull_sql(
            device_name, zone_pairs, since_iso, until_iso
        )
        raw_rows = self._ch.run(candidate_sql, candidate_params)["rows"]
        candidates = _aggregate_candidates(raw_rows)

        cutoff_by_zone_pair = {zp: cutoff for zp in zone_pairs} if cutoff else {}

        return evaluate_change_impact(
            device_name=device_name,
            provider=provider,
            p_rules=p_rules,
            pprime_rules=pprime_rules,
            object_book=object_book,
            candidates=candidates,
            window_since=since_iso,
            window_until=until_iso,
            delta_payload=delta_payload,
            cutoff_by_zone_pair=cutoff_by_zone_pair,
            deny_logging_observed=deny_logging_observed or {},
            coverage={"window_default_days": DEFAULT_WINDOW_DAYS if since is None else None},
        )
