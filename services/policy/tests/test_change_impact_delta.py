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
    new_rule = _rule("NEW")
    del new_rule["position"]  # assigned by list order ('before'/'after'), not caller input
    delta = parse_json_delta([{"op": "add", "rule": new_rule, "before": "B"}])
    result = apply_delta(rules, delta)
    assert [r["rule_name"] for r in result] == ["A", "NEW", "B"]


def test_json_add_rejects_caller_supplied_position():
    """A new rule's position is derived from list order ('before'/'after'),
    never from the caller's dict -- the caller-supplied value used to win
    silently (defaulting to 0, evaluated first, regardless of 'before'), or
    crash `int(None)` if the dict explicitly set it to None."""
    with pytest.raises(DeltaError):
        parse_json_delta([{"op": "add", "rule": _rule("NEW"), "before": "B"}])


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
# junos_current_text must be security-policies-only
# ---------------------------------------------------------------------------


def test_validate_security_policies_only_accepts_pure_policy_text():
    validate_security_policies_only(BASE_TEXT)  # must not raise


def test_validate_security_policies_only_rejects_non_policy_lines():
    """A full `show configuration | display set` dump (as opposed to the
    requested `security policies` subtree) can carry device secrets outside
    the policy stanza. The tool must refuse it outright rather than silently
    dropping the unrecognized lines the way the internal grouping does."""
    tainted = BASE_TEXT + "\nset system root-authentication encrypted-password REDACTED-NOT-REAL"
    with pytest.raises(DeltaError):
        validate_security_policies_only(tainted)


def test_apply_junos_text_delta_rejects_full_config_dump():
    tainted = BASE_TEXT + "\nset snmp community public authorization read-only"
    with pytest.raises(DeltaError):
        apply_junos_text_delta(tainted, [], "vsrx-ci", "2026-10-03T00:00:00")


def test_validate_security_policies_only_error_never_contains_rejected_line_text():
    """The mcp-query wrapper records `str(exc)` in `ssdf.audit` unredacted,
    so a refusal triggered by a secret-bearing line must identify that line
    by position only, never by echoing its text."""
    secret = "set security ike policy P pre-shared-key ascii-text REDACTED-NOT-REAL"
    tainted = BASE_TEXT + "\n" + secret
    with pytest.raises(DeltaError) as excinfo:
        validate_security_policies_only(tainted)
    assert secret not in str(excinfo.value)
    assert "REDACTED-NOT-REAL" not in str(excinfo.value)


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


def test_apply_junos_set_delta_error_never_contains_rejected_line_text():
    """F5 regression: `apply_junos_text_delta`'s caller (the mcp-query
    wrapper) records `str(exc)` in `ssdf.audit` verbatim, so a rejection
    raised here must identify the bad line by position only."""
    secret = "frobnicate pre-shared-key REDACTED-NOT-REAL"
    with pytest.raises(DeltaError) as excinfo:
        apply_junos_set_delta(BASE_TEXT, [secret])
    assert secret not in str(excinfo.value)
    assert "REDACTED-NOT-REAL" not in str(excinfo.value)
    assert "line 1" in str(excinfo.value)


# ---------------------------------------------------------------------------
# F2: Junos `insert` ambiguity -- a bare policy name used in more than one
# from-zone/to-zone context must be refused, never silently resolved to the
# first match. The full Junos form resolves by the fully zone-qualified key
# and so is never ambiguous.
# ---------------------------------------------------------------------------

_AMBIGUOUS_NAME_TEXT = """
set security policies from-zone trust to-zone untrust policy X then permit
set security policies from-zone trust to-zone untrust policy Y then permit
set security policies from-zone dmz to-zone untrust policy X then deny
""".strip()


def test_junos_insert_short_form_ambiguous_name_is_rejected():
    with pytest.raises(DeltaError):
        apply_junos_set_delta(_AMBIGUOUS_NAME_TEXT, ["insert X before Y"])


def test_junos_insert_full_form_disambiguates_by_zone_pair():
    new_text = apply_junos_set_delta(
        _AMBIGUOUS_NAME_TEXT,
        ["insert security policies from-zone trust to-zone untrust policy X before policy Y"],
    )
    rules = parse_security_policies(new_text, "vsrx-ci", "2026-10-03T00:00:00")
    trust_rules = sorted(
        (r for r in rules if r["from_zone"] == ["trust"]), key=lambda r: r["position"]
    )
    assert [r["rule_name"] for r in trust_rules] == ["X", "Y"]
    # The unrelated dmz->untrust policy also named X is untouched.
    dmz_x = next(r for r in rules if r["from_zone"] == ["dmz"])
    assert dmz_x["action"] == "deny"


def test_junos_insert_full_form_global_policy():
    text = """
    set security policies global policy X then permit
    set security policies global policy Y then permit
    """.strip()
    new_text = apply_junos_set_delta(
        text, ["insert security policies global policy Y before policy X"]
    )
    rules = parse_security_policies(new_text, "vsrx-ci", "2026-10-03T00:00:00")
    by_position = sorted(rules, key=lambda r: r["position"])
    assert [r["rule_name"] for r in by_position] == ["Y", "X"]


# ---------------------------------------------------------------------------
# F3: sub-statement activate/deactivate and prefix-style sub-statement delete
# must be refused, not silently mis-applied to the whole policy / silently
# dropped as a no-op.
# ---------------------------------------------------------------------------


def test_junos_deactivate_sub_statement_is_rejected():
    """Deactivating one clause of a policy is not the same as deactivating
    the whole policy -- Junos narrows the match, this code must not pretend
    the whole rule went inactive."""
    with pytest.raises(DeltaError):
        apply_junos_set_delta(
            BASE_TEXT,
            [
                "deactivate security policies from-zone trust to-zone untrust policy "
                "ALLOW-WEB match application junos-http"
            ],
        )


def test_junos_activate_sub_statement_is_rejected():
    with pytest.raises(DeltaError):
        apply_junos_set_delta(
            BASE_TEXT,
            [
                "activate security policies from-zone trust to-zone untrust policy "
                "ALLOW-WEB match application junos-http"
            ],
        )


def test_junos_delete_prefix_style_sub_statement_with_no_value_is_rejected():
    """`delete ... policy X match source-address` with no trailing value is a
    truncated paste of a Junos hierarchical delete, not a request to remove
    one specific address entry. Silently matching nothing (the old
    behaviour) reads as "nothing to delete" when the real problem is an
    incomplete delta line."""
    with pytest.raises(DeltaError):
        apply_junos_set_delta(
            BASE_TEXT,
            [
                "delete security policies from-zone trust to-zone untrust policy "
                "ALLOW-WEB match source-address"
            ],
        )


GLOBAL_TEXT = """
set security policies global policy G match from-zone trust
set security policies global policy G match to-zone untrust
set security policies global policy G then permit
set security policies global policy G then log session-close
""".strip()


def test_junos_delete_sub_statement_that_matches_no_line_is_rejected():
    """A sub-statement delete whose tail doesn't exactly match any existing
    line must be refused, not applied as a silent no-op -- an operator
    pasting the wrong tail (or a typo) must not have the delta report P' == P
    while believing a restriction was removed."""
    with pytest.raises(DeltaError):
        apply_junos_set_delta(
            GLOBAL_TEXT,
            ["delete security policies global policy G match from-zone"],
        )


def test_junos_delete_sub_statement_log_tail_with_no_matching_line_is_rejected():
    with pytest.raises(DeltaError):
        apply_junos_set_delta(
            GLOBAL_TEXT,
            ["delete security policies global policy G then log"],
        )


def test_junos_delete_sub_statement_exact_match_is_applied():
    """The positive case: a delete whose tail exactly matches an existing
    line is applied normally."""
    result = apply_junos_set_delta(
        GLOBAL_TEXT,
        ["delete security policies global policy G match from-zone trust"],
    )
    assert "match from-zone trust" not in result
    assert "match to-zone untrust" in result


# ---------------------------------------------------------------------------
# MEC-1776 review fixes
# ---------------------------------------------------------------------------


def test_junos_delete_of_unknown_whole_policy_is_rejected():
    """A typo'd delete target used to be silently dropped as a no-op
    (`if key not in index: continue`), making P' == P even though the caller
    believed a policy was removed. It must be refused instead."""
    with pytest.raises(DeltaError):
        apply_junos_set_delta(
            BASE_TEXT,
            ["delete security policies from-zone trust to-zone untrust policy GHOST"],
        )


def test_junos_delete_of_unknown_policy_sub_statement_is_rejected():
    with pytest.raises(DeltaError):
        apply_junos_set_delta(
            BASE_TEXT,
            [
                "delete security policies from-zone trust to-zone untrust policy GHOST "
                "match application any"
            ],
        )


def test_junos_insert_short_form_before_itself_is_rejected():
    """`insert P1 before P1` used to raise a bare `StopIteration` from
    `next()` once the moved group was popped out from under the sibling
    lookup -- it must raise `DeltaError` instead."""
    with pytest.raises(DeltaError):
        apply_junos_set_delta(BASE_TEXT, ["insert ALLOW-WEB before ALLOW-WEB"])


def test_junos_insert_full_form_after_itself_is_rejected():
    with pytest.raises(DeltaError):
        apply_junos_set_delta(
            BASE_TEXT,
            [
                "insert security policies from-zone trust to-zone untrust policy ALLOW-WEB "
                "after policy ALLOW-WEB"
            ],
        )


def test_json_modify_rejects_internal_fields():
    """A delta must not be able to clear `match_unknown` (or set `is_global`,
    `provider`, `vendor_extras`, `rule_name`) via `modify.fields` -- those are
    collector-derived bookkeeping the evaluator trusts, not match/action/
    enabled clauses a proposed change can describe."""
    with pytest.raises(DeltaError):
        parse_json_delta([{"op": "modify", "rule_name": "A", "fields": {"match_unknown": False}}])
    with pytest.raises(DeltaError):
        parse_json_delta([{"op": "modify", "rule_name": "A", "fields": {"is_global": True}}])
    with pytest.raises(DeltaError):
        parse_json_delta([{"op": "modify", "rule_name": "A", "fields": {"provider": "paloalto"}}])
    with pytest.raises(DeltaError):
        parse_json_delta([{"op": "modify", "rule_name": "A", "fields": {"vendor_extras": {}}}])
    with pytest.raises(DeltaError):
        parse_json_delta([{"op": "modify", "rule_name": "A", "fields": {"rule_name": "B"}}])
    # The positive case: an allowed match/action/enabled field still works.
    parse_json_delta([{"op": "modify", "rule_name": "A", "fields": {"action": "deny"}}])
