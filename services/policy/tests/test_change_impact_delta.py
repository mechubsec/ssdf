"""Delta parsing/application (doc §1.1b): the JSON op list and the Junos
`set`/`delete`/`insert ... before|after`/`activate`/`deactivate` text form.
Delta never reaches a device anywhere in this module -- these tests only ever
exercise in-memory rule lists.
"""

import pytest

from ssdf_policy.change_impact.delta import (
    DeltaError,
    apply_delta,
    apply_junos_set_delta,
    apply_junos_text_delta,
    parse_json_delta,
    validate_security_policies_only,
)
from ssdf_policy.collectors.junos import parse_security_policies

BASE_TEXT = """
set security policies from-zone trust to-zone untrust policy ALLOW-WEB match source-address any
set security policies from-zone trust to-zone untrust policy ALLOW-WEB match destination-address any
set security policies from-zone trust to-zone untrust policy ALLOW-WEB match application junos-http
set security policies from-zone trust to-zone untrust policy ALLOW-WEB then permit
set security policies from-zone trust to-zone untrust policy DENY-ALL match source-address any
set security policies from-zone trust to-zone untrust policy DENY-ALL match destination-address any
set security policies from-zone trust to-zone untrust policy DENY-ALL match application any
set security policies from-zone trust to-zone untrust policy DENY-ALL then deny
""".strip()


def _rule(name, **overrides):
    rule = {
        "provider": "juniper",
        "device_name": "vsrx-ci",
        "rule_name": name,
        "action": "allow",
        "from_zone": ["trust"],
        "to_zone": ["untrust"],
        "source_addresses": [],
        "dest_addresses": [],
        "application": [],
        "service": [],
        "position": 0,
        "enabled": True,
        "vendor_extras": {},
        "collected_at": "2026-10-03T00:00:00",
        "is_global": False,
        "source_address_excluded": False,
        "dest_address_excluded": False,
        "source_identity": [],
        "dynamic_application": [],
        "url_category": [],
        "source_end_user_profile": [],
        "scheduler_name": "",
        "match_unknown": False,
    }
    rule.update(overrides)
    return rule


# ---------------------------------------------------------------------------
# JSON op list
# ---------------------------------------------------------------------------


def test_json_add_inserts_before_named_rule():
    rules = [_rule("A"), _rule("B")]
    delta = parse_json_delta([{"op": "add", "rule": _rule("NEW"), "before": "B"}])
    result = apply_delta(rules, delta)
    assert [r["rule_name"] for r in result] == ["A", "NEW", "B"]


def test_json_delete_removes_rule():
    rules = [_rule("A"), _rule("B")]
    delta = parse_json_delta([{"op": "delete", "rule_name": "A"}])
    result = apply_delta(rules, delta)
    assert [r["rule_name"] for r in result] == ["B"]


def test_json_modify_updates_fields_without_mutating_input():
    rules = [_rule("A", action="allow")]
    delta = parse_json_delta([{"op": "modify", "rule_name": "A", "fields": {"action": "deny"}}])
    result = apply_delta(rules, delta)
    assert result[0]["action"] == "deny"
    assert rules[0]["action"] == "allow"  # pure: input untouched


def test_json_enable_disable():
    rules = [_rule("A", enabled=False)]
    delta = parse_json_delta([{"op": "enable", "rule_name": "A"}])
    assert apply_delta(rules, delta)[0]["enabled"] is True


def test_json_move_before():
    rules = [_rule("A"), _rule("B"), _rule("C")]
    delta = parse_json_delta([{"op": "move", "rule_name": "C", "before": "A"}])
    result = apply_delta(rules, delta)
    assert [r["rule_name"] for r in result] == ["C", "A", "B"]


def test_json_delta_rejects_unknown_op():
    with pytest.raises(DeltaError):
        parse_json_delta([{"op": "frobnicate", "rule_name": "A"}])


def test_json_delta_rejects_ambiguous_rule_name_across_contexts():
    rules = [
        _rule("DUP", from_zone=["trust"], to_zone=["untrust"]),
        _rule("DUP", from_zone=["dmz"], to_zone=["untrust"]),
    ]
    delta = parse_json_delta([{"op": "delete", "rule_name": "DUP"}])
    with pytest.raises(DeltaError):
        apply_delta(rules, delta)
    # Disambiguated by from_zone, it resolves cleanly.
    delta_ok = parse_json_delta([{"op": "delete", "rule_name": "DUP", "from_zone": "dmz"}])
    result = apply_delta(rules, delta_ok)
    assert len(result) == 1 and result[0]["from_zone"] == ["trust"]


def test_json_delta_rejects_modify_with_empty_fields():
    with pytest.raises(DeltaError):
        parse_json_delta([{"op": "modify", "rule_name": "A", "fields": {}}])


# ---------------------------------------------------------------------------
# Junos `| display set` text delta
# ---------------------------------------------------------------------------


def test_junos_set_lines_add_a_new_policy():
    delta_lines = [
        "set security policies from-zone trust to-zone untrust policy NEW-RULE match source-address any",
        "set security policies from-zone trust to-zone untrust policy NEW-RULE match destination-address any",
        "set security policies from-zone trust to-zone untrust policy NEW-RULE match application any",
        "set security policies from-zone trust to-zone untrust policy NEW-RULE then deny",
    ]
    p, pprime = apply_junos_text_delta(BASE_TEXT, delta_lines, "vsrx-ci", "2026-10-03T00:00:00")
    assert {r["rule_name"] for r in p} == {"ALLOW-WEB", "DENY-ALL"}
    assert {r["rule_name"] for r in pprime} == {"ALLOW-WEB", "DENY-ALL", "NEW-RULE"}


def test_junos_delete_whole_policy_removes_it():
    new_text = apply_junos_set_delta(
        BASE_TEXT,
        ["delete security policies from-zone trust to-zone untrust policy DENY-ALL"],
    )
    rules = parse_security_policies(new_text, "vsrx-ci", "2026-10-03T00:00:00")
    assert {r["rule_name"] for r in rules} == {"ALLOW-WEB"}


# ---------------------------------------------------------------------------
# MEC-1644 F4: junos_current_text must be security-policies-only
# ---------------------------------------------------------------------------


def test_validate_security_policies_only_accepts_pure_policy_text():
    validate_security_policies_only(BASE_TEXT)  # must not raise


def test_validate_security_policies_only_rejects_non_policy_lines():
    """A full `show configuration | display set` dump (as opposed to the
    requested `security policies` subtree) can carry IKE PSKs or SNMP
    communities. The tool must refuse it outright rather than silently
    dropping the unrecognized lines the way the internal grouping does."""
    tainted = BASE_TEXT + "\nset system root-authentication encrypted-password REDACTED-NOT-REAL"
    with pytest.raises(DeltaError):
        validate_security_policies_only(tainted)


def test_apply_junos_text_delta_rejects_full_config_dump():
    tainted = BASE_TEXT + "\nset snmp community public authorization read-only"
    with pytest.raises(DeltaError):
        apply_junos_text_delta(tainted, [], "vsrx-ci", "2026-10-03T00:00:00")


def test_junos_delete_one_clause_leaves_the_rest():
    new_text = apply_junos_set_delta(
        BASE_TEXT,
        [
            "delete security policies from-zone trust to-zone untrust policy ALLOW-WEB "
            "match application junos-http"
        ],
    )
    rules = parse_security_policies(new_text, "vsrx-ci", "2026-10-03T00:00:00")
    web = next(r for r in rules if r["rule_name"] == "ALLOW-WEB")
    assert web["application"] == []
    assert web["action"] == "allow"  # the `then permit` line is untouched


def test_junos_deactivate_then_activate_round_trips():
    deactivated = apply_junos_set_delta(
        BASE_TEXT,
        ["deactivate security policies from-zone trust to-zone untrust policy ALLOW-WEB"],
    )
    rules = parse_security_policies(deactivated, "vsrx-ci", "2026-10-03T00:00:00")
    assert next(r for r in rules if r["rule_name"] == "ALLOW-WEB")["enabled"] is False

    reactivated = apply_junos_set_delta(
        deactivated,
        ["activate security policies from-zone trust to-zone untrust policy ALLOW-WEB"],
    )
    rules = parse_security_policies(reactivated, "vsrx-ci", "2026-10-03T00:00:00")
    assert next(r for r in rules if r["rule_name"] == "ALLOW-WEB")["enabled"] is True


def test_junos_insert_before_reorders_without_changing_content():
    new_text = apply_junos_set_delta(
        BASE_TEXT,
        ["insert DENY-ALL before ALLOW-WEB"],
    )
    rules = parse_security_policies(new_text, "vsrx-ci", "2026-10-03T00:00:00")
    by_position = sorted(rules, key=lambda r: r["position"])
    assert [r["rule_name"] for r in by_position] == ["DENY-ALL", "ALLOW-WEB"]
    # Content is untouched by the reorder.
    web = next(r for r in rules if r["rule_name"] == "ALLOW-WEB")
    assert web["application"] == ["junos-http"]


def test_junos_insert_after_reorders():
    text = """
    set security policies from-zone trust to-zone untrust policy A then permit
    set security policies from-zone trust to-zone untrust policy B then permit
    set security policies from-zone trust to-zone untrust policy C then deny
    """.strip()
    new_text = apply_junos_set_delta(text, ["insert A after C"])
    rules = parse_security_policies(new_text, "vsrx-ci", "2026-10-03T00:00:00")
    by_position = sorted(rules, key=lambda r: r["position"])
    assert [r["rule_name"] for r in by_position] == ["B", "C", "A"]


def test_junos_set_delta_rejects_unrecognized_line():
    with pytest.raises(DeltaError):
        apply_junos_set_delta(BASE_TEXT, ["frobnicate security policies ..."])


def test_junos_set_delta_rejects_insert_of_unknown_policy():
    with pytest.raises(DeltaError):
        apply_junos_set_delta(BASE_TEXT, ["insert GHOST before ALLOW-WEB"])
