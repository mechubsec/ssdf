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

from ssdf_policy.change_impact import compile_rulebase, diff_rulebases, evaluate_change_impact
from ssdf_policy.change_impact.delta import (
    apply_delta,
    apply_junos_text_delta,
    parse_json_delta,
    renumber_positions,
)

from .change_impact_builders import (
    DEFAULT_CANDIDATE_LIMIT,
    build_candidate_pull_sql,
    build_latest_object_book_sql,
    build_policy_version_cutoff_sql,
    policy_entity_to_rule,
)
from .timeparse import parse_time

DEFAULT_WINDOW_DAYS = 14  # doc §4: raw-events default until flow_tuples_daily (task B) lands

# `event_action` values the candidate pull's own query already filters on
# (see change_impact_builders.build_candidate_pull_sql) that represent a
# logged deny/drop, as opposed to a session close.
_DENY_ACTIONS = frozenset({"flow_session_deny", "flow_deny", "flow_drop"})


class ChangeImpactError(ValueError):
    pass


def _deny_logging_observed(rows: list[dict]) -> dict[tuple[str, str], bool]:
    """Per zone-pair: was any deny/drop logged in-window? (doc §6 deny-side
    blindness input.) Computed here, from the same candidate rows the
    evaluator already scores, rather than taken as an MCP caller argument --
    a model-supplied value for this would let model output decide whether a
    widened rule's newly-allowed traffic is reported as a number or
    "unknown"."""
    observed: dict[tuple[str, str], bool] = {}
    for row in rows:
        if row.get("event_action") in _DENY_ACTIONS:
            zp = (row.get("observer_ingress_zone"), row.get("observer_egress_zone"))
            observed[zp] = True
    return observed


def _aggregate_candidates(rows: list[dict], provider: str) -> list[dict]:
    """Group raw `ssdf.events` rows into effective-tuple candidates (doc §1.3).

    `provider` is always the tool call's own argument, never read off the row.

    v1 does this in Python rather than pushing the NAT-aware GROUP BY into
    ClickHouse (see change_impact_builders.build_candidate_pull_sql docstring)
    -- correct, not yet the scale-optimized form doc §2.1 describes.
    """
    from ssdf_policy.change_impact.flowtuple import effective_tuple

    buckets: dict[tuple, dict] = {}
    for row in rows:
        tup = effective_tuple(row, provider)
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
        # The caller's `provider` argument picks the vendor semantics this
        # device is evaluated under; it must agree with what was actually
        # stored for this device, not be trusted on its own.
        stored_providers = {item["policy"].get("attrs", {}).get("provider") for item in items}
        if items and not any(stored_providers):
            raise ChangeImpactError(
                f"stored configuration for device {device_name!r} has no recorded provider"
            )
        for stored_provider in stored_providers:
            if stored_provider and stored_provider != provider:
                raise ChangeImpactError(
                    f"provider {provider!r} does not match the stored provider "
                    f"{stored_provider!r} for device {device_name!r}"
                )
        rules = [policy_entity_to_rule(item["policy"], device_name, provider) for item in items]
        # `configured_policies_for_firewalls` returns entities in SQL join
        # order, not rulebase order -- `renumber_positions` puts P onto the
        # same position scale `apply_delta` produces for P', trusting each
        # policy's stored `attrs["position"]`, not list order.
        return renumber_positions(rules)

    def _reconcile_junos_baseline(
        self, device_name: str, provider: str, text_rules: list[dict]
    ) -> None:
        """Refuse a Junos text-form baseline (`junos_current_text`) that
        doesn't match the stored configuration for this device, including
        its per-context rule order (first-match depends on it).

        The text form lets the caller paste the device's own config instead
        of re-reading the store, but that text then becomes P for the
        config-only pre-check (`evaluator.config_only_precheck`), which can
        return a "provably no impact" verdict before any traffic is looked
        at. Compared on `(context, rule_name)` plus content and per-context
        order, ignoring `position`'s absolute scale (not comparable between
        the two sources) and `collected_at` (a parse timestamp, not state).
        """
        stored_rules = self._configured_rules(device_name, provider)
        stored_compiled = compile_rulebase(stored_rules, {})
        text_compiled = compile_rulebase(renumber_positions(text_rules), {})
        ignored_fields = {
            "position",
            "collected_at",
            # PAN-OS-only NormalizedRule fields (collectors/panos.py):
            # `policy_entity_to_rule` always fills these in (defaulting
            # false/empty) regardless of provider, but the Junos text-form
            # parser (collectors/junos.py `_new_rule`) never produces these
            # keys at all -- comparing them would make every genuinely
            # matching Junos baseline look like a mismatch.
            "negate_source",
            "negate_destination",
            "schedule",
        }

        def _snapshot(compiled):
            return {
                (c.context, c.rule_name): {
                    k: v for k, v in c.raw.items() if k not in ignored_fields
                }
                for c in compiled
            }

        def _order_by_context(compiled):
            by_context: dict = {}
            for c in sorted(compiled, key=lambda c: c.position):
                by_context.setdefault(c.context, []).append(c.rule_name)
            return by_context

        if _snapshot(stored_compiled) != _snapshot(text_compiled) or _order_by_context(
            stored_compiled
        ) != _order_by_context(text_compiled):
            raise ChangeImpactError(
                "junos_current_text does not match the stored configuration for this device"
            )

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
    ) -> dict:
        """`delta` is either the vendor-neutral JSON op list (a list of op
        dicts) or, for Junos text form, a dict `{"lines": [...]}` -- requires
        `junos_current_text` (the device's current `| display set` output)
        since that form diffs text, not the stored rule list.
        """
        since_was_default = since is None
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
            # The text form's P comes from caller-supplied text, not the
            # store -- verify it actually matches the stored configuration
            # before it's allowed to drive a config-only "no impact" verdict.
            self._reconcile_junos_baseline(device_name, provider, p_rules)
            delta_payload = delta
        elif isinstance(delta, list):
            p_rules = self._configured_rules(device_name, provider)
            delta_obj = parse_json_delta(delta, provider)
            pprime_rules = apply_delta(p_rules, delta_obj, provider=provider)
            delta_payload = delta
        else:
            raise ChangeImpactError(
                "delta must be a JSON op list, or {'lines': [...]} for the Junos text form"
            )

        object_book = self._object_book(provider, device_name)

        # Restrict the candidate pull's zone-pairs to C, the rules that
        # actually differ between P and P': scoping to the whole rulebase's
        # zone-pairs would pull far more of the flow log than needed and risk
        # truncating at DEFAULT_CANDIDATE_LIMIT before the window closed.
        diff_result = diff_rulebases(
            compile_rulebase(p_rules, object_book), compile_rulebase(pprime_rules, object_book)
        )
        changed_names = diff_result.changed_rule_names
        coverage = {"window_default_days": DEFAULT_WINDOW_DAYS if since_was_default else None}

        if not changed_names:
            # A delta that resolves to no rule-level change (e.g. a typo'd
            # delete target already refused, or ops that cancel out) must not
            # fall through to an unscoped candidate pull (zone clause `1=1`
            # when `zone_pairs` is empty) -- `evaluate_change_impact` reports
            # this explicitly without any ClickHouse I/O.
            return evaluate_change_impact(
                device_name=device_name,
                provider=provider,
                p_rules=p_rules,
                pprime_rules=pprime_rules,
                object_book=object_book,
                candidates=[],
                window_since=since_iso,
                window_until=until_iso,
                delta_payload=delta_payload,
                cutoff=None,
                deny_logging_observed={},
                coverage=coverage,
                truncated=False,
                truncated_at=None,
            )

        all_names = sorted(
            {r["rule_name"] for r in p_rules} | {r["rule_name"] for r in pprime_rules}
        )
        cutoff_sql, cutoff_params = build_policy_version_cutoff_sql(device_name, all_names)
        cutoff_rows = self._ch.run(cutoff_sql, cutoff_params)["rows"]
        cutoff = cutoff_rows[0]["cutoff"] if cutoff_rows and cutoff_rows[0].get("cutoff") else None

        p_changed = [r for r in p_rules if r["rule_name"] in changed_names]
        pprime_changed = [r for r in pprime_rules if r["rule_name"] in changed_names]
        zone_pairs = sorted(set(self._zone_pairs(p_changed) + self._zone_pairs(pprime_changed)))

        candidate_sql, candidate_params = build_candidate_pull_sql(
            device_name, zone_pairs, since_iso, until_iso
        )
        raw_rows = self._ch.run(candidate_sql, candidate_params)["rows"]
        truncated = len(raw_rows) > DEFAULT_CANDIDATE_LIMIT
        if truncated:
            raw_rows = raw_rows[:DEFAULT_CANDIDATE_LIMIT]
        candidates = _aggregate_candidates(raw_rows, provider)
        deny_logging_observed = _deny_logging_observed(raw_rows)

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
            # `cutoff` is one device-level value, applied uniformly across
            # every zone-pair in the calibration gate.
            cutoff=cutoff,
            deny_logging_observed=deny_logging_observed,
            coverage=coverage,
            truncated=truncated,
            truncated_at=DEFAULT_CANDIDATE_LIMIT if truncated else None,
        )
