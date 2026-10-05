from ssdf_policy.resolve_policies import resolve_policies
from ssdf_policy.models import entity_id, ASSET, POLICY, FIREWALL, CONFIGURED
from ssdf_policy.collectors.panos import parse_security_rules


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


def test_panos_rule_from_parse_security_rules_resolves_without_keyerror():
    """MEC-1834: a real PAN-OS rule dict (as produced by
    collectors.panos.parse_security_rules) has `match_unknown` set but none of
    the Junos-only match-clause keys, so resolve_policies must not assume the
    whole Junos group is present just because `match_unknown` is. It must also
    surface PAN-OS's own clauses (negate_source/schedule/url_category/
    source_user/source_hip/destination_hip) instead of silently dropping
    them."""
    xml = (
        "<rules>"
        "<entry name='allow-web' uuid='u-1'>"
        "<from><member>trust</member></from>"
        "<to><member>untrust</member></to>"
        "<source><member>any</member></source>"
        "<destination><member>any</member></destination>"
        "<application><member>web-browsing</member></application>"
        "<service><member>application-default</member></service>"
        "<action>allow</action>"
        "<negate-source>yes</negate-source>"
        "<schedule>business-hours</schedule>"
        "<category><member>malware</member></category>"
        "<source-user><member>any</member></source-user>"
        "<source-hip><member>hip-profile-1</member></source-hip>"
        "<destination-hip><member>any</member></destination-hip>"
        "</entry>"
        "</rules>"
    )
    rules = parse_security_rules(xml, "panosvm", "2026-06-08T00:00:00")
    entities, _ = resolve_policies(rules, "t_main")
    pol = next(e for e in entities if e["kind"] == POLICY)
    assert pol["source"] == CONFIGURED
    attrs = pol["attrs"]
    assert attrs["match_unknown"] == "true"
    assert attrs["negate_source"] == "true"
    assert attrs["negate_destination"] == "false"
    assert attrs["schedule"] == "business-hours"
    assert attrs["url_category"] == "malware"
    assert attrs["source_hip"] == "hip-profile-1"
    # no Junos-only keys leaked onto a PAN-OS entity
    assert "source_address_excluded" not in attrs
    assert "scheduler_name" not in attrs


def test_junos_match_clause_attrs_still_populate():
    """Guard regression: per-key presence checks must not stop populating the
    Junos attrs that were already working before MEC-1834."""
    rule = {
        **_rule("vsrx-ci", "RESTRICTED-RULE", provider="juniper"),
        "match_unknown": True,
        "source_address_excluded": True,
        "dest_address_excluded": False,
        "source_identity": ["eng-group"],
        "dynamic_application": ["junos:FACEBOOK"],
        "url_category": ["Enhanced_Gambling"],
        "source_end_user_profile": ["corp-laptop"],
        "scheduler_name": "weekends",
    }
    entities, _ = resolve_policies([rule], "t_main")
    pol = next(e for e in entities if e["kind"] == POLICY)
    attrs = pol["attrs"]
    assert attrs["match_unknown"] == "true"
    assert attrs["source_address_excluded"] == "true"
    assert attrs["dest_address_excluded"] == "false"
    assert attrs["source_identity"] == "eng-group"
    assert attrs["dynamic_application"] == "junos:FACEBOOK"
    assert attrs["url_category"] == "Enhanced_Gambling"
    assert attrs["source_end_user_profile"] == "corp-laptop"
    assert attrs["scheduler_name"] == "weekends"
