"""diff_rulebases identity invariant (doc §1.4 / diff.py module docstring):
identity is `(context, rule_name)`, so two rules sharing that identity on
either side of the diff must never be silently collapsed into one.
"""

import pytest

from ssdf_policy.change_impact.diff import DiffError, diff_rulebases
from ssdf_policy.change_impact.rulemodel import compile_rulebase

EMPTY_BOOK = {}


def _rule(name, action="deny", **overrides):
    rule = {
        "provider": "juniper",
        "device_name": "vsrx-ci",
        "rule_name": name,
        "action": action,
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


def test_diff_rulebases_rejects_duplicate_identity_in_pprime():
    """Defence in depth (F1 part 2): even if a caller of `diff_rulebases`
    manages to produce a P' with two rules sharing one (context, rule_name)
    identity -- e.g. a `modify` that moves a rule's zones onto another
    rule's identity -- the diff must refuse rather than have the later rule
    in the dict comprehension silently win and hide the collision."""
    p_rules = [_rule("A", action="deny", position=0)]
    pprime_rules = [
        _rule("A", action="deny", position=0),
        _rule("A", action="allow", position=1),
    ]
    p_compiled = compile_rulebase(p_rules, EMPTY_BOOK)
    pprime_compiled = compile_rulebase(pprime_rules, EMPTY_BOOK)
    with pytest.raises(DiffError):
        diff_rulebases(p_compiled, pprime_compiled)


def test_diff_rulebases_rejects_duplicate_identity_in_p():
    p_rules = [
        _rule("A", action="deny", position=0),
        _rule("A", action="allow", position=1),
    ]
    pprime_rules = [_rule("A", action="deny", position=0)]
    p_compiled = compile_rulebase(p_rules, EMPTY_BOOK)
    pprime_compiled = compile_rulebase(pprime_rules, EMPTY_BOOK)
    with pytest.raises(DiffError):
        diff_rulebases(p_compiled, pprime_compiled)


def test_diff_rulebases_allows_same_name_in_different_contexts():
    p_rules = [_rule("A", from_zone=["trust"], to_zone=["untrust"])]
    pprime_rules = [
        _rule("A", from_zone=["trust"], to_zone=["untrust"]),
        _rule("A", from_zone=["dmz"], to_zone=["untrust"], position=1),
    ]
    p_compiled = compile_rulebase(p_rules, EMPTY_BOOK)
    pprime_compiled = compile_rulebase(pprime_rules, EMPTY_BOOK)
    result = diff_rulebases(p_compiled, pprime_compiled)
    assert result.added == {"A"}
    assert "A" in result.ambiguous_names
