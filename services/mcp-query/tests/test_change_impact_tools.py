"""ChangeImpactTools tests (MEC-1640, task C of MEC-570): the ClickHouse/
entity-store I/O glue around the pure `ssdf_policy.change_impact` evaluator.

Mirrors test_rule_tools.py's Fake client pattern. The adapter from
configured-policy entity attrs back to a NormalizedRule dict
(`change_impact_builders.policy_entity_to_rule`) is the one genuinely new
piece of I/O-adjacent logic here -- these tests exercise it end to end rather
than only in isolation.
"""

import json

from ssdf_mcp_query.change_impact_builders import policy_entity_to_rule
from ssdf_mcp_query.change_impact_tools import ChangeImpactTools


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
