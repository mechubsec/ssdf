"""ChangeImpactTools tests (MEC-1640, task C of MEC-570): the ClickHouse/
entity-store I/O glue around the pure `ssdf_policy.change_impact` evaluator.

Mirrors test_rule_tools.py's Fake client pattern. The adapter from
configured-policy entity attrs back to a NormalizedRule dict
(`change_impact_builders.policy_entity_to_rule`) is the one genuinely new
piece of I/O-adjacent logic here -- these tests exercise it end to end rather
than only in isolation.
"""

import json

import pytest

from ssdf_mcp_query.change_impact_builders import policy_entity_to_rule
from ssdf_mcp_query.change_impact_tools import (
    ChangeImpactError,
    ChangeImpactTools,
    _aggregate_candidates,
)


class FakeChClient:
    def __init__(self, object_book=None, cutoff=None, event_rows=None):
        self._object_book = object_book if object_book is not None else {}
        self._cutoff = cutoff
        self._event_rows = event_rows or []
        self.calls = []

    def run(self, sql, params=None):
        params = params or {}
        self.calls.append((sql, params))
        if "object_book_hash" in sql:
            if not self._object_book:
                return {"columns": [], "rows": [], "row_count": 0}
            rows = [
                {"object_book": json.dumps(self._object_book), "valid_from": "2026-09-01T00:00:00"}
            ]
            return {"columns": [], "rows": rows, "row_count": 1}
        if "policy_versions" in sql:
            rows = [{"cutoff": self._cutoff}] if self._cutoff else [{"cutoff": None}]
            return {"columns": [], "rows": rows, "row_count": 1}
        if "ssdf.events" in sql:
            return {"columns": [], "rows": self._event_rows, "row_count": len(self._event_rows)}
        raise AssertionError(f"unexpected sql: {sql}")


class FakeEntityStore:
    def __init__(self, policies):
        self._policies = policies

    def configured_policies_for_firewalls(self, firewall_names):
        return [{"firewall": firewall_names[0], "policy": p} for p in self._policies]


def _policy_entity(name, action="deny", application="", enabled="true", match_unknown="false"):
    return {
        "name": name,
        "attrs": {
            "provider": "juniper",
            "device_name": "vsrx-ci",
            "action": action,
            "from_zone": "trust",
            "to_zone": "untrust",
            "source_addresses": "",
            "dest_addresses": "",
            "application": application,
            "service": application,
            "position": "0",
            "enabled": enabled,
            "match_unknown": match_unknown,
            "source_address_excluded": "false",
            "dest_address_excluded": "false",
            "source_identity": "",
            "dynamic_application": "",
            "url_category": "",
            "source_end_user_profile": "",
            "scheduler_name": "",
        },
    }


def test_policy_entity_to_rule_round_trips_scalar_and_list_fields():
    entity = _policy_entity("RULE-A", action="allow", application="junos-http")
    rule = policy_entity_to_rule(entity, "vsrx-ci", "juniper")
    assert rule["rule_name"] == "RULE-A"
    assert rule["action"] == "allow"
    assert rule["application"] == ["junos-http"]
    assert rule["from_zone"] == ["trust"]
    assert rule["enabled"] is True
    assert rule["match_unknown"] is False


def test_change_impact_json_delta_end_to_end_with_fakes():
    policies = [_policy_entity("RULE-A", action="deny")]
    store = FakeEntityStore(policies)
    object_book = {"address_books": {"global": {"addresses": {}, "address_sets": {}}}}
    event_rows = [
        {
            "observer_ingress_zone": "trust",
            "observer_egress_zone": "untrust",
            "source_ip": "10.1.1.5",
            "destination_ip": "10.2.2.5",
            "network_transport": "tcp",
            "destination_port": 443,
            "ext": {},
            "rule_name": "RULE-A",
            "timestamp": "2026-09-25T00:00:00",
        }
        for _ in range(150)
    ]
    ch = FakeChClient(object_book=object_book, event_rows=event_rows)
    tools = ChangeImpactTools(ch, store)

    report = tools.change_impact(
        device_name="vsrx-ci",
        provider="juniper",
        delta=[{"op": "modify", "rule_name": "RULE-A", "fields": {"action": "allow"}}],
        since="2026-09-20T00:00:00",
        until="2026-10-03T00:00:00",
    )
    assert report["device_name"] == "vsrx-ci"
    [section] = report["changed_rules"]
    assert section["rule_name"] == "RULE-A"
    # 150 sessions, all logged against RULE-A, 100% agreement with the
    # evaluator's own P-verdict -> calibration passes and the verdict change
    # (deny -> allow) is reported, not downgraded to unknown.
    assert "verdict_change_opens" in section["classes"]
    assert section["classes"]["verdict_change_opens"]["sessions"] == 150


def test_policy_entity_to_rule_reads_is_global_from_attrs_not_from_zone_heuristic():
    """A global policy with an explicit `match from-zone X` (from_zone !=
    'any') must still read back as global -- re-deriving it from from_zone
    would misclassify it as a zone-pair rule."""
    entity = _policy_entity("GLOBAL-RULE", action="deny")
    entity["attrs"]["is_global"] = "true"
    rule = policy_entity_to_rule(entity, "vsrx-ci", "juniper")
    assert rule["is_global"] is True

    entity2 = _policy_entity("ZONEPAIR-RULE", action="deny")
    entity2["attrs"]["is_global"] = "false"
    rule2 = policy_entity_to_rule(entity2, "vsrx-ci", "juniper")
    assert rule2["is_global"] is False


def test_change_impact_deny_logging_observed_is_computed_from_candidate_rows():
    """F4 regression: whether a zone-pair had any logged deny must come from
    the candidate rows the evaluator itself already scored, never a
    caller-supplied argument (a model-controlled value could otherwise turn
    an honest "unknown" into a fabricated count)."""
    policies = [_policy_entity("NARROW", action="deny")]
    store = FakeEntityStore(policies)
    object_book = {"address_books": {"global": {"addresses": {}, "address_sets": {}}}}
    event_rows = [
        {
            "observer_ingress_zone": "trust",
            "observer_egress_zone": "untrust",
            "source_ip": "10.1.1.5",
            "destination_ip": "10.2.2.5",
            "network_transport": "tcp",
            "destination_port": 443,
            "ext": {},
            "rule_name": "NARROW",
            "event_action": "flow_session_deny",
            "timestamp": "2026-09-25T00:00:00",
        }
        for _ in range(150)
    ]
    ch = FakeChClient(object_book=object_book, event_rows=event_rows)
    tools = ChangeImpactTools(ch, store)

    report = tools.change_impact(
        device_name="vsrx-ci",
        provider="juniper",
        delta=[{"op": "modify", "rule_name": "NARROW", "fields": {"action": "allow"}}],
        since="2026-09-20T00:00:00",
        until="2026-10-03T00:00:00",
    )
    blindness = report["deny_side_blindness"]
    assert blindness, "expected a deny-side-blindness entry for an opens class"
    for entry in blindness.values():
        assert entry["deny_logging_observed"] is True
        assert entry["newly_allowed_sessions"] == 150

    # The tool no longer accepts a caller-supplied value for this at all.
    with pytest.raises(TypeError):
        tools.change_impact(
            device_name="vsrx-ci",
            provider="juniper",
            delta=[{"op": "modify", "rule_name": "NARROW", "fields": {"action": "allow"}}],
            deny_logging_observed={("trust", "untrust"): True},
        )


def test_change_impact_reports_default_window_only_when_since_omitted():
    """F7 regression: `coverage.window_default_days` must say whether the
    14-day default was actually used, not always read None because `since`
    had already been defaulted by the time the check ran."""
    policies = [_policy_entity("RULE-A", action="deny")]
    store = FakeEntityStore(policies)
    object_book = {"address_books": {"global": {"addresses": {}, "address_sets": {}}}}
    ch = FakeChClient(object_book=object_book, event_rows=[])
    tools = ChangeImpactTools(ch, store)
    delta = [{"op": "modify", "rule_name": "RULE-A", "fields": {"action": "allow"}}]

    default_report = tools.change_impact(device_name="vsrx-ci", provider="juniper", delta=delta)
    assert default_report["coverage"]["window_default_days"] == 14

    explicit_report = tools.change_impact(
        device_name="vsrx-ci",
        provider="juniper",
        delta=delta,
        since="2026-09-20T00:00:00",
        until="2026-10-03T00:00:00",
    )
    assert explicit_report["coverage"]["window_default_days"] is None


def test_change_impact_truncated_pull_is_reported_not_hidden():
    """When the candidate pull returns more rows than the cap, the report
    must say so instead of reading as a real 'no sessions observed'."""
    policies = [_policy_entity("RULE-A", action="deny")]
    store = FakeEntityStore(policies)
    object_book = {"address_books": {"global": {"addresses": {}, "address_sets": {}}}}
    # These rows sit on a zone-pair RULE-A's rule never covers, and are never
    # logged against RULE-A -- firstmatch3 can neither match nor touch RULE-A
    # for them (before/after both fall through to default-deny with no rule
    # name), so the only question this test asks is whether the resulting
    # empty section reads as "no sessions" or "truncated".
    event_rows = [
        {
            "observer_ingress_zone": "dmz",
            "observer_egress_zone": "other",
            "source_ip": f"10.1.1.{i % 200}",
            "destination_ip": "10.2.2.5",
            "network_transport": "tcp",
            "destination_port": 443,
            "ext": {},
            "rule_name": "SOME-OTHER-RULE",
            "timestamp": "2026-09-25T00:00:00",
        }
        for i in range(3)
    ]
    ch = FakeChClient(object_book=object_book, event_rows=event_rows)
    tools = ChangeImpactTools(ch, store)
    import ssdf_mcp_query.change_impact_tools as cit_module

    original_limit = cit_module.DEFAULT_CANDIDATE_LIMIT
    cit_module.DEFAULT_CANDIDATE_LIMIT = 2  # force the fake 3-row pull to look truncated
    try:
        report = tools.change_impact(
            device_name="vsrx-ci",
            provider="juniper",
            delta=[{"op": "modify", "rule_name": "RULE-A", "fields": {"action": "allow"}}],
            since="2026-09-20T00:00:00",
            until="2026-10-03T00:00:00",
        )
    finally:
        cit_module.DEFAULT_CANDIDATE_LIMIT = original_limit

    assert report["truncated"] is True
    [section] = report["changed_rules"]
    assert section["result"] == "unknown: candidate pull truncated at 2 rows"


def test_change_impact_zone_pairs_restricted_to_changed_rules():
    """The candidate pull's zone-pair filter must come from the rules that
    actually differ (C), not the whole rulebase -- an unrelated zone-pair
    with no changed rule must not widen (or narrow) the pull."""
    policies = [
        _policy_entity("RULE-A", action="deny"),
        {
            **_policy_entity("RULE-UNRELATED", action="deny"),
            "attrs": {
                **_policy_entity("RULE-UNRELATED")["attrs"],
                "from_zone": "dmz",
                "to_zone": "trust",
            },
        },
    ]
    store = FakeEntityStore(policies)
    object_book = {"address_books": {"global": {"addresses": {}, "address_sets": {}}}}
    ch = FakeChClient(object_book=object_book, event_rows=[])
    tools = ChangeImpactTools(ch, store)

    tools.change_impact(
        device_name="vsrx-ci",
        provider="juniper",
        delta=[{"op": "modify", "rule_name": "RULE-A", "fields": {"action": "allow"}}],
        since="2026-09-20T00:00:00",
        until="2026-10-03T00:00:00",
    )
    [events_call] = [call for call in ch.calls if "ssdf.events" in call[0]]
    _sql, params = events_call
    # Only RULE-A (trust->untrust) changed; RULE-UNRELATED's dmz->trust
    # zone-pair must not appear in the candidate pull's predicate.
    assert params.get("ingress_0") == "trust"
    assert params.get("egress_0") == "untrust"
    assert "ingress_1" not in params


def test_change_impact_junos_text_baseline_mismatched_with_store_is_refused():
    """A `junos_current_text` baseline that disagrees with the stored
    configuration must be refused, not trusted."""
    p1 = _policy_entity("P1", action="allow")
    p1["attrs"]["source_addresses"] = "any"
    p1["attrs"]["dest_addresses"] = "any"
    p1["attrs"]["application"] = "any"
    p1["attrs"]["service"] = "any"
    store = FakeEntityStore([p1])
    ch = FakeChClient()
    tools = ChangeImpactTools(ch, store)

    junos_current_text = """
    inactive: set security policies from-zone trust to-zone untrust policy P1 match source-address any
    inactive: set security policies from-zone trust to-zone untrust policy P1 match destination-address any
    inactive: set security policies from-zone trust to-zone untrust policy P1 match application any
    inactive: set security policies from-zone trust to-zone untrust policy P1 then permit
    """
    with pytest.raises(ChangeImpactError) as excinfo:
        tools.change_impact(
            device_name="vsrx-ci",
            provider="juniper",
            delta={"lines": ["delete security policies from-zone trust to-zone untrust policy P1"]},
            junos_current_text=junos_current_text,
            since="2026-09-20T00:00:00",
            until="2026-10-03T00:00:00",
        )
    assert "does not match the stored configuration" in str(excinfo.value)


def test_change_impact_junos_text_baseline_matching_store_is_accepted():
    """The positive case for the above: when the pasted text does agree with
    the store, the call proceeds normally instead of being refused."""
    p1 = _policy_entity("P1", action="allow")
    p1["attrs"]["source_addresses"] = "any"
    p1["attrs"]["dest_addresses"] = "any"
    p1["attrs"]["application"] = "any"
    p1["attrs"]["service"] = "any"
    store = FakeEntityStore([p1])
    object_book = {"address_books": {"global": {"addresses": {}, "address_sets": {}}}}
    ch = FakeChClient(object_book=object_book, event_rows=[])
    tools = ChangeImpactTools(ch, store)

    junos_current_text = """
    set security policies from-zone trust to-zone untrust policy P1 match source-address any
    set security policies from-zone trust to-zone untrust policy P1 match destination-address any
    set security policies from-zone trust to-zone untrust policy P1 match application any
    set security policies from-zone trust to-zone untrust policy P1 then permit
    """
    report = tools.change_impact(
        device_name="vsrx-ci",
        provider="juniper",
        delta={"lines": ["delete security policies from-zone trust to-zone untrust policy P1"]},
        junos_current_text=junos_current_text,
        since="2026-09-20T00:00:00",
        until="2026-10-03T00:00:00",
    )
    assert report["device_name"] == "vsrx-ci"


def _trust_untrust_rule(name, action, position, src):
    rule = _policy_entity(name, action=action)
    rule["attrs"]["position"] = str(position)
    rule["attrs"]["source_addresses"] = src
    rule["attrs"]["dest_addresses"] = "any"
    rule["attrs"]["application"] = "any"
    rule["attrs"]["service"] = "any"
    return rule


_A_LINES = """set security policies from-zone trust to-zone untrust policy A match source-address 10.0.0.1
set security policies from-zone trust to-zone untrust policy A match destination-address any
set security policies from-zone trust to-zone untrust policy A match application any
set security policies from-zone trust to-zone untrust policy A then permit"""

_B_LINES = """set security policies from-zone trust to-zone untrust policy B match source-address 10.0.0.2
set security policies from-zone trust to-zone untrust policy B match destination-address any
set security policies from-zone trust to-zone untrust policy B match application any
set security policies from-zone trust to-zone untrust policy B then permit"""

_C_LINES = """set security policies from-zone trust to-zone untrust policy C match source-address any
set security policies from-zone trust to-zone untrust policy C match destination-address any
set security policies from-zone trust to-zone untrust policy C match application any
set security policies from-zone trust to-zone untrust policy C then deny"""


def test_change_impact_junos_text_baseline_reordered_within_context_is_refused():
    """A pasted baseline whose per-rule content matches the stored
    configuration but whose first-match order within a context does not
    must still be refused."""
    store = FakeEntityStore(
        [
            _trust_untrust_rule("A", "allow", 0, "10.0.0.1"),
            _trust_untrust_rule("C", "deny", 1, "any"),
            _trust_untrust_rule("B", "allow", 2, "10.0.0.2"),
        ]
    )
    ch = FakeChClient()
    tools = ChangeImpactTools(ch, store)

    # Store order is A, C, B; the pasted text lists A, B, C.
    junos_current_text = "\n".join([_A_LINES, _B_LINES, _C_LINES])
    with pytest.raises(ChangeImpactError) as excinfo:
        tools.change_impact(
            device_name="vsrx-ci",
            provider="juniper",
            delta={"lines": []},
            junos_current_text=junos_current_text,
            since="2026-09-20T00:00:00",
            until="2026-10-03T00:00:00",
        )
    assert "does not match the stored configuration" in str(excinfo.value)


def test_change_impact_junos_text_baseline_matching_order_reorder_delta_is_not_config_only():
    """The positive case: a baseline whose order matches the store is
    accepted, and a delta that reorders a rule past a rule with different
    behaviour must not be reported as provably no impact."""
    store = FakeEntityStore(
        [
            _trust_untrust_rule("A", "allow", 0, "10.0.0.1"),
            _trust_untrust_rule("C", "deny", 1, "any"),
            _trust_untrust_rule("B", "allow", 2, "10.0.0.2"),
        ]
    )
    object_book = {"address_books": {"global": {"addresses": {}, "address_sets": {}}}}
    ch = FakeChClient(object_book=object_book, event_rows=[])
    tools = ChangeImpactTools(ch, store)

    # Store and text order both A, C, B.
    junos_current_text = "\n".join([_A_LINES, _C_LINES, _B_LINES])
    report = tools.change_impact(
        device_name="vsrx-ci",
        provider="juniper",
        delta={
            "lines": [
                "insert security policies from-zone trust to-zone untrust policy B before policy A"
            ]
        },
        junos_current_text=junos_current_text,
        since="2026-09-20T00:00:00",
        until="2026-10-03T00:00:00",
    )
    for section in report["changed_rules"]:
        assert section.get("result") != "provably no impact (config-only)"


def test_change_impact_rejects_provider_mismatched_with_stored_policy():
    """The caller's `provider` argument must agree with what was actually
    stored for this device, not be trusted on its own."""
    policies = [_policy_entity("RULE-A", action="deny")]  # stored provider: juniper
    store = FakeEntityStore(policies)
    ch = FakeChClient()
    tools = ChangeImpactTools(ch, store)

    with pytest.raises(ChangeImpactError) as excinfo:
        tools.change_impact(
            device_name="vsrx-ci",
            provider="paloalto",
            delta=[{"op": "modify", "rule_name": "RULE-A", "fields": {"action": "allow"}}],
            since="2026-09-20T00:00:00",
            until="2026-10-03T00:00:00",
        )
    assert "does not match the stored provider" in str(excinfo.value)


def test_change_impact_junos_text_delta_requires_current_text():
    store = FakeEntityStore([])
    ch = FakeChClient()
    tools = ChangeImpactTools(ch, store)
    try:
        tools.change_impact(
            device_name="vsrx-ci",
            provider="juniper",
            delta={
                "lines": [
                    "set security policies from-zone trust to-zone untrust policy X then deny"
                ]
            },
        )
    except Exception as exc:
        assert "junos_current_text" in str(exc)
    else:
        raise AssertionError("expected an error without junos_current_text")


def test_change_impact_rejects_device_with_no_recorded_provider():
    """A device whose stored policies carry no provider attribute at all
    must be refused rather than trusting the caller's `provider` argument
    unconditionally."""
    policies = [_policy_entity("RULE-A", action="deny")]
    del policies[0]["attrs"]["provider"]
    store = FakeEntityStore(policies)
    ch = FakeChClient()
    tools = ChangeImpactTools(ch, store)

    with pytest.raises(ChangeImpactError) as excinfo:
        tools.change_impact(
            device_name="vsrx-ci",
            provider="juniper",
            delta=[{"op": "modify", "rule_name": "RULE-A", "fields": {"action": "allow"}}],
            since="2026-09-20T00:00:00",
            until="2026-10-03T00:00:00",
        )
    assert "no recorded provider" in str(excinfo.value)


def test_aggregate_candidates_derives_panos_app_from_ext():
    """PAN-OS candidates must be aggregated with PAN-OS tuple semantics
    (the `provider` passed in), not whatever default `effective_tuple`
    would otherwise fall back to."""
    rows = [
        {
            "observer_ingress_zone": "trust",
            "observer_egress_zone": "untrust",
            "source_ip": "10.1.1.5",
            "destination_ip": "10.2.2.5",
            "network_transport": "tcp",
            "destination_port": 443,
            "ext": {"panw.panos.application": "ssl"},
            "rule_name": "RULE-A",
            "timestamp": "2026-09-25T00:00:00",
        }
    ]
    [candidate] = _aggregate_candidates(rows, "paloalto")
    assert candidate["tuple"].app == "ssl"


def test_change_impact_json_delta_with_no_net_rule_change_skips_events_query():
    """A delta that nets to no rule-level change must not fall through to
    an unscoped candidate pull."""
    policies = [_policy_entity("RULE-A", action="deny")]
    store = FakeEntityStore(policies)
    ch = FakeChClient()
    tools = ChangeImpactTools(ch, store)

    report = tools.change_impact(
        device_name="vsrx-ci",
        provider="juniper",
        delta=[
            {"op": "disable", "rule_name": "RULE-A"},
            {"op": "enable", "rule_name": "RULE-A"},
        ],
        since="2026-09-20T00:00:00",
        until="2026-10-03T00:00:00",
    )
    assert report["note"] == "delta produces no rule change"
    assert not any("ssdf.events" in call[0] for call in ch.calls)
