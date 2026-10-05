from ssdf_policy.resolve_policies import resolve_policies
from ssdf_policy.models import entity_id, ASSET, POLICY, FIREWALL


def _rule(device, name, provider="paloalto", action="allow"):
    return {
        "provider": provider,
        "device_name": device,
        "rule_name": name,
        "action": action,
        "from_zone": ["trust"],
        "to_zone": ["untrust"],
        "source_addresses": ["any"],
        "dest_addresses": ["10.64.0.0/24"],
        "application": ["web-browsing"],
        "service": ["http"],
        "position": 0,
        "enabled": True,
        "vendor_extras": {"panw.panos.uuid": "u-1"},
        "collected_at": "2026-06-08T00:00:00",
    }


def test_same_rule_name_on_two_firewalls_does_not_collapse():
    rules = [
        _rule("fwA", "ALLOW-WEB", provider="juniper"),
        _rule("fwB", "ALLOW-WEB", provider="juniper"),
    ]
    entities, _ = resolve_policies(rules, "t_main")
    policies = [e for e in entities if e["kind"] == POLICY]
    assert len({p["entity_id"] for p in policies}) == 2  # the M6a collapse is fixed


def test_emits_firewall_entity_and_governed_by_edge():
    entities, edges = resolve_policies([_rule("panosvm", "allow-web")], "t_main")
    kinds = {e["kind"] for e in entities}
    assert kinds == {FIREWALL, POLICY}
    fw = next(e for e in entities if e["kind"] == FIREWALL)
    pol = next(e for e in entities if e["kind"] == POLICY)
    assert fw["entity_id"] == entity_id("t_main", FIREWALL, "device:panosvm")
    assert fw["identifiers"]["device_name"] == "panosvm"
    assert pol["entity_id"] == entity_id("t_main", POLICY, "paloalto:panosvm:allow-web")
    assert pol["source"] == "configured"
    assert pol["attrs"]["action"] == "allow"
    assert pol["attrs"]["from_zone"] == "trust"
    assert pol["attrs"]["dest_addresses"] == "10.64.0.0/24"
    assert pol["attrs"]["enabled"] == "true"
    assert pol["attrs"]["position"] == "0"
    assert len(edges) == 1
    edge = edges[0]
    assert edge["edge_type"] == "governed_by" and edge["source"] == "configured"
    assert edge["src_id"] == fw["entity_id"] and edge["dst_id"] == pol["entity_id"]


def test_idempotent_ids_across_runs():
    rules = [_rule("panosvm", "allow-web")]
    e1, _ = resolve_policies(rules, "t_main")
    e2, _ = resolve_policies(rules, "t_main")
    assert {e["entity_id"] for e in e1} == {e["entity_id"] for e in e2}


def test_no_asset_entities_emitted():
    entities, _ = resolve_policies([_rule("panosvm", "allow-web")], "t_main")
    assert not any(e["kind"] == ASSET for e in entities)


def test_is_global_is_persisted_on_the_policy_entity():
    """change_impact reads `is_global` back from the entity rather than
    re-deriving it from `from_zone`, so the collector's own classification
    must survive the round-trip through resolve_policies."""
    global_rule = {**_rule("vsrx-ci", "GLOBAL-RULE", provider="juniper"), "is_global": True}
    zonepair_rule = {**_rule("vsrx-ci", "ZONEPAIR-RULE", provider="juniper"), "is_global": False}
    entities, _ = resolve_policies([global_rule, zonepair_rule], "t_main")
    attrs_by_name = {e["name"]: e["attrs"] for e in entities if e["kind"] == POLICY}
    assert attrs_by_name["GLOBAL-RULE"]["is_global"] == "true"
    assert attrs_by_name["ZONEPAIR-RULE"]["is_global"] == "false"
