"""Golden cases for change_impact (MEC-1640, task C of MEC-570).

change_impact is the safety-critical tool in MEC-570: a wrong "0 historical
sessions affected" is the kind of finding that gets a firewall rule deleted
(doc `change-impact-scope` on MEC-986). These tests hold the evaluator to the
same fail-closed bar `unused_rules` was held to in MEC-566/MEC-724 -- every
case here either proves "no impact" without guessing, or refuses to guess at
all and says `unknown`.
"""

import re

import pytest

from ssdf_policy.change_impact import (
    CONFIG_ONLY_NO_IMPACT,
    NO_RULE_CHANGE,
    NO_SESSIONS_OBSERVED,
    apply_delta,
    evaluate_change_impact,
    parse_json_delta,
)
from ssdf_policy.change_impact.rulemodel import compile_rulebase
from ssdf_policy.collectors.junos import parse_security_policies

EMPTY_BOOK = {"address_books": {"global": {"addresses": {}, "address_sets": {}}}}
NOW = "2026-10-03T00:00:00"


def _junos_rules(text: str) -> list[dict]:
    return parse_security_policies(text.strip(), "vsrx-ci", NOW)


def _json_rule(name: str, action: str, position: int, **overrides) -> dict:
    """A NormalizedRule-shaped dict for the JSON-delta form (mirrors
    test_change_impact_delta.py's `_rule`, duplicated here since that's a
    different test module)."""
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
        "position": position,
        "enabled": True,
        "vendor_extras": {},
        "collected_at": NOW,
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


def _candidate(
    *,
    ingress_zone="trust",
    egress_zone="untrust",
    src_ip="10.1.1.5",
    dst_ip="10.2.2.5",
    transport="tcp",
    dst_port=443,
    sessions=10,
    logged_rules=(),
    first_seen="2026-09-20T00:00:00",
    last_seen="2026-09-25T00:00:00",
):
    return {
        "tuple": {
            "observer_ingress_zone": ingress_zone,
            "observer_egress_zone": egress_zone,
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "network_transport": transport,
            "destination_port": dst_port,
            "ext": {},
        },
        "sessions": sessions,
        "bytes": sessions * 1000,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "logged_rules": list(logged_rules),
    }


# ---------------------------------------------------------------------------
# Golden case 1: reorder-only, no impact
# ---------------------------------------------------------------------------


def test_reorder_of_same_action_rules_is_provably_no_impact():
    text_before = """
    set security policies from-zone trust to-zone untrust policy ALLOW-WEB match source-address any
    set security policies from-zone trust to-zone untrust policy ALLOW-WEB match destination-address any
    set security policies from-zone trust to-zone untrust policy ALLOW-WEB match application any
    set security policies from-zone trust to-zone untrust policy ALLOW-WEB then permit
    set security policies from-zone trust to-zone untrust policy ALLOW-DNS match source-address any
    set security policies from-zone trust to-zone untrust policy ALLOW-DNS match destination-address any
    set security policies from-zone trust to-zone untrust policy ALLOW-DNS match application any
    set security policies from-zone trust to-zone untrust policy ALLOW-DNS then permit
    """
    text_after = """
    set security policies from-zone trust to-zone untrust policy ALLOW-DNS match source-address any
    set security policies from-zone trust to-zone untrust policy ALLOW-DNS match destination-address any
    set security policies from-zone trust to-zone untrust policy ALLOW-DNS match application any
    set security policies from-zone trust to-zone untrust policy ALLOW-DNS then permit
    set security policies from-zone trust to-zone untrust policy ALLOW-WEB match source-address any
    set security policies from-zone trust to-zone untrust policy ALLOW-WEB match destination-address any
    set security policies from-zone trust to-zone untrust policy ALLOW-WEB match application any
    set security policies from-zone trust to-zone untrust policy ALLOW-WEB then permit
    """
    report = evaluate_change_impact(
        device_name="vsrx-ci",
        provider="juniper",
        p_rules=_junos_rules(text_before),
        pprime_rules=_junos_rules(text_after),
        object_book=EMPTY_BOOK,
        candidates=[],  # must never be touched: the config-only pre-check short-circuits
        window_since="2026-09-20T00:00:00",
        window_until="2026-10-03T00:00:00",
        delta_payload={"kind": "reorder-test"},
    )
    assert {s["rule_name"]: s["result"] for s in report["changed_rules"]} == {
        "ALLOW-WEB": CONFIG_ONLY_NO_IMPACT,
        "ALLOW-DNS": CONFIG_ONLY_NO_IMPACT,
    }


# ---------------------------------------------------------------------------
# A benign reorder must not cause an unrelated, enabled rule insertion in the
# same delta to be reported as "provably no impact".
# ---------------------------------------------------------------------------


def test_reorder_with_unrelated_enabled_insert_is_not_config_only():
    text_before = """
    set security policies from-zone trust to-zone untrust policy A match source-address any
    set security policies from-zone trust to-zone untrust policy A match destination-address any
    set security policies from-zone trust to-zone untrust policy A match application any
    set security policies from-zone trust to-zone untrust policy A then permit
    set security policies from-zone trust to-zone untrust policy B match source-address any
    set security policies from-zone trust to-zone untrust policy B match destination-address any
    set security policies from-zone trust to-zone untrust policy B match application any
    set security policies from-zone trust to-zone untrust policy B then permit
    """
    # A and B swap order (a benign reorder: both permit) AND a new, enabled
    # DENY-ALL is inserted ahead of both. The precheck must account for every
    # changed rule in the delta, not just the reordered pair, so DENY-ALL
    # (which now intercepts all zone-pair traffic ahead of A) must not be
    # stamped CONFIG_ONLY_NO_IMPACT.
    text_after = """
    set security policies from-zone trust to-zone untrust policy DENY-ALL match source-address any
    set security policies from-zone trust to-zone untrust policy DENY-ALL match destination-address any
    set security policies from-zone trust to-zone untrust policy DENY-ALL match application any
    set security policies from-zone trust to-zone untrust policy DENY-ALL then deny
    set security policies from-zone trust to-zone untrust policy B match source-address any
    set security policies from-zone trust to-zone untrust policy B match destination-address any
    set security policies from-zone trust to-zone untrust policy B match application any
    set security policies from-zone trust to-zone untrust policy B then permit
    set security policies from-zone trust to-zone untrust policy A match source-address any
    set security policies from-zone trust to-zone untrust policy A match destination-address any
    set security policies from-zone trust to-zone untrust policy A match application any
    set security policies from-zone trust to-zone untrust policy A then permit
    """
    candidates = [_candidate(sessions=500, logged_rules=["A"])]
    report = evaluate_change_impact(
        device_name="vsrx-ci",
        provider="juniper",
        p_rules=_junos_rules(text_before),
        pprime_rules=_junos_rules(text_after),
        object_book=EMPTY_BOOK,
        candidates=candidates,
        window_since="2026-09-20T00:00:00",
        window_until="2026-10-03T00:00:00",
        delta_payload={"kind": "f1-reorder-plus-insert"},
    )
    by_name = {s["rule_name"]: s for s in report["changed_rules"]}
    assert set(by_name) == {"A", "B", "DENY-ALL"}
    for section in by_name.values():
        assert section.get("result") != CONFIG_ONLY_NO_IMPACT, (
            "an enabled, unrelated rule insertion must force full candidate "
            "evaluation, never ride a sibling rule's benign reorder"
        )
    # DENY-ALL now matches first on this zone-pair and blocks what A used to
    # permit -- the real, unhidden verdict change.
    deny_all_classes = by_name["DENY-ALL"]["classes"]
    assert "verdict_change_breaks" in deny_all_classes
    assert deny_all_classes["verdict_change_breaks"]["sessions"] == 500
    _assert_honesty_contract(report)


# ---------------------------------------------------------------------------
# A rule that is both modified AND reordered must not ride the reorder
# branch's pairwise check -- that check only proves equivalence for a pure
# position swap of otherwise-unchanged rules.
# ---------------------------------------------------------------------------


def test_reorder_with_unrelated_enabled_insert_is_not_config_only_modified_in_pair():
    text_before = """
    set security policies from-zone trust to-zone untrust policy A match source-address any
    set security policies from-zone trust to-zone untrust policy A match destination-address any
    set security policies from-zone trust to-zone untrust policy A match application any
    set security policies from-zone trust to-zone untrust policy A then permit
    set security policies from-zone trust to-zone untrust policy B match source-address any
    set security policies from-zone trust to-zone untrust policy B match destination-address any
    set security policies from-zone trust to-zone untrust policy B match application any
    set security policies from-zone trust to-zone untrust policy B then deny
    """
    # B and A swap order AND A's own action changes (permit -> deny). A
    # taking part in the reorder must not exempt it from the "must be
    # disabled in both" content-change check -- the pairwise reorder check
    # alone cannot prove that A's own action change is equivalence-preserving.
    text_after = """
    set security policies from-zone trust to-zone untrust policy B match source-address any
    set security policies from-zone trust to-zone untrust policy B match destination-address any
    set security policies from-zone trust to-zone untrust policy B match application any
    set security policies from-zone trust to-zone untrust policy B then deny
    set security policies from-zone trust to-zone untrust policy A match source-address any
    set security policies from-zone trust to-zone untrust policy A match destination-address any
    set security policies from-zone trust to-zone untrust policy A match application any
    set security policies from-zone trust to-zone untrust policy A then deny
    """
    candidates = [_candidate(sessions=500, logged_rules=["A"])]
    report = evaluate_change_impact(
        device_name="vsrx-ci",
        provider="juniper",
        p_rules=_junos_rules(text_before),
        pprime_rules=_junos_rules(text_after),
        object_book=EMPTY_BOOK,
        candidates=candidates,
        window_since="2026-09-20T00:00:00",
        window_until="2026-10-03T00:00:00",
        delta_payload={"kind": "r1-modified-and-reordered"},
    )
    by_name = {s["rule_name"]: s for s in report["changed_rules"]}
    assert set(by_name) == {"A", "B"}
    for section in by_name.values():
        assert section.get("result") != CONFIG_ONLY_NO_IMPACT, (
            "a rule that is both modified and reordered must force full "
            "candidate evaluation, never ride its own reorder"
        )
    # A used to permit this traffic; now B (deny, any/any/any) matches first.
    assert "verdict_change_breaks" in by_name["A"]["classes"]
    assert by_name["A"]["classes"]["verdict_change_breaks"]["sessions"] == 500
    _assert_honesty_contract(report)


# ---------------------------------------------------------------------------
# The same rule name in two different zone-pair contexts must never be
# treated as one rule by the config-only pre-check or the report's per-rule
# bucketing.
# ---------------------------------------------------------------------------


def test_same_rule_name_in_two_contexts_is_not_config_only_or_merged():
    text_before = """
    set security policies from-zone trust to-zone untrust policy A match source-address any
    set security policies from-zone trust to-zone untrust policy A match destination-address any
    set security policies from-zone trust to-zone untrust policy A match application any
    set security policies from-zone trust to-zone untrust policy A then permit
    inactive: set security policies from-zone dmz to-zone untrust policy X match source-address any
    inactive: set security policies from-zone dmz to-zone untrust policy X match destination-address any
    inactive: set security policies from-zone dmz to-zone untrust policy X match application any
    inactive: set security policies from-zone dmz to-zone untrust policy X then deny
    """
    # A new, enabled policy also named X is added to trust->untrust, while an
    # unrelated, long-inactive dmz->untrust policy is also named X. A
    # bare-name lookup must not conflate the two: the pre-check (and,
    # separately, per-rule report bucketing) must refuse to answer about
    # either rule by name alone.
    text_after = (
        text_before
        + """
    set security policies from-zone trust to-zone untrust policy X match source-address any
    set security policies from-zone trust to-zone untrust policy X match destination-address any
    set security policies from-zone trust to-zone untrust policy X match application any
    set security policies from-zone trust to-zone untrust policy X then deny
    """
    )
    candidates = [_candidate(sessions=500, logged_rules=["X"])]
    report = evaluate_change_impact(
        device_name="vsrx-ci",
        provider="juniper",
        p_rules=_junos_rules(text_before),
        pprime_rules=_junos_rules(text_after),
        object_book=EMPTY_BOOK,
        candidates=candidates,
        window_since="2026-09-20T00:00:00",
        window_until="2026-10-03T00:00:00",
        delta_payload={"kind": "r2-ambiguous-name"},
    )
    by_name = {s["rule_name"]: s for s in report["changed_rules"]}
    assert set(by_name) == {"X"}
    assert by_name["X"]["result"] != CONFIG_ONLY_NO_IMPACT
    # Must refuse to attribute traffic to either same-named rule rather than
    # silently merging them, and must not guess a session count either way.
    assert by_name["X"].get("classes") is None
    assert "unknown" in by_name["X"]["result"]
    _assert_honesty_contract(report)


# ---------------------------------------------------------------------------
# Golden case 2: editing a rule that stays disabled, no impact
# ---------------------------------------------------------------------------


def test_editing_a_rule_disabled_in_both_versions_is_provably_no_impact():
    text_before = """
    inactive: set security policies from-zone trust to-zone dmz policy OLD-RULE match source-address any
    inactive: set security policies from-zone trust to-zone dmz policy OLD-RULE match destination-address any
    inactive: set security policies from-zone trust to-zone dmz policy OLD-RULE match application any
    inactive: set security policies from-zone trust to-zone dmz policy OLD-RULE then permit
    """
    text_after = """
    inactive: set security policies from-zone trust to-zone dmz policy OLD-RULE match source-address any
    inactive: set security policies from-zone trust to-zone dmz policy OLD-RULE match destination-address 10.5.5.0/24
    inactive: set security policies from-zone trust to-zone dmz policy OLD-RULE match application any
    inactive: set security policies from-zone trust to-zone dmz policy OLD-RULE then permit
    """
    report = evaluate_change_impact(
        device_name="vsrx-ci",
        provider="juniper",
        p_rules=_junos_rules(text_before),
        pprime_rules=_junos_rules(text_after),
        object_book=EMPTY_BOOK,
        candidates=[],
        window_since="2026-09-20T00:00:00",
        window_until="2026-10-03T00:00:00",
        delta_payload={"kind": "disabled-edit-test"},
    )
    assert report["changed_rules"] == [{"rule_name": "OLD-RULE", "result": CONFIG_ONLY_NO_IMPACT}]


# ---------------------------------------------------------------------------
# Golden case 3: deny-side blindness honesty wording
# ---------------------------------------------------------------------------


def test_widened_rule_with_no_logged_denies_reports_unknown_not_zero():
    text_before = """
    set security policies from-zone trust to-zone untrust policy NARROW match source-address any
    set security policies from-zone trust to-zone untrust policy NARROW match destination-address any
    set security policies from-zone trust to-zone untrust policy NARROW match application junos-https
    set security policies from-zone trust to-zone untrust policy NARROW then deny
    set security policies from-zone trust to-zone untrust policy CATCH-ALL match source-address any
    set security policies from-zone trust to-zone untrust policy CATCH-ALL match destination-address any
    set security policies from-zone trust to-zone untrust policy CATCH-ALL match application any
    set security policies from-zone trust to-zone untrust policy CATCH-ALL then deny
    """
    text_after = """
    set security policies from-zone trust to-zone untrust policy NARROW match source-address any
    set security policies from-zone trust to-zone untrust policy NARROW match destination-address any
    set security policies from-zone trust to-zone untrust policy NARROW match application junos-https
    set security policies from-zone trust to-zone untrust policy NARROW then permit
    set security policies from-zone trust to-zone untrust policy CATCH-ALL match source-address any
    set security policies from-zone trust to-zone untrust policy CATCH-ALL match destination-address any
    set security policies from-zone trust to-zone untrust policy CATCH-ALL match application any
    set security policies from-zone trust to-zone untrust policy CATCH-ALL then deny
    """
    book = {
        "address_books": {"global": {"addresses": {}, "address_sets": {}}},
        "predefined_applications": {
            "junos-https": {"kind": "application", "protocol": "tcp", "destination_port": "443"}
        },
        "predefined_application_sets": {},
        "applications": {},
        "application_sets": {},
    }
    # No session in this candidate was ever logged against NARROW with a deny
    # outcome -- the zone-pair simply never had deny logging turned on, which
    # the caller signals via an empty `deny_logging_observed` map.
    candidates = [
        _candidate(dst_port=443, sessions=50, logged_rules=["NARROW"]),
    ]
    report = evaluate_change_impact(
        device_name="vsrx-ci",
        provider="juniper",
        p_rules=_junos_rules(text_before),
        pprime_rules=_junos_rules(text_after),
        object_book=book,
        candidates=candidates,
        window_since="2026-09-20T00:00:00",
        window_until="2026-10-03T00:00:00",
        delta_payload={"kind": "deny-blindness-test"},
        deny_logging_observed={},  # nothing observed logging denies in-window
        calibration_min_sample=1,
    )
    blindness = report["deny_side_blindness"]
    assert blindness, "expected a deny-side-blindness entry for an opens class"
    for entry in blindness.values():
        assert entry["deny_logging_observed"] is False
        assert entry["newly_allowed_sessions"] == "unknown"

    dump = str(report)
    # The honesty contract (doc §1.6): "safe"/"no impact" never appear except
    # the one approved config-only phrase, and a deny-blind count is never 0.
    assert "0 newly allowed" not in dump
    _assert_honesty_contract(report)


# ---------------------------------------------------------------------------
# Golden case 4: calibration-gate failure forces unknown
# ---------------------------------------------------------------------------


def test_calibration_gate_failure_downgrades_zone_pair_to_unknown():
    text_before = """
    set security policies from-zone trust to-zone untrust policy RULE-X match source-address any
    set security policies from-zone trust to-zone untrust policy RULE-X match destination-address any
    set security policies from-zone trust to-zone untrust policy RULE-X match application any
    set security policies from-zone trust to-zone untrust policy RULE-X then deny
    """
    text_after = """
    set security policies from-zone trust to-zone untrust policy RULE-X match source-address any
    set security policies from-zone trust to-zone untrust policy RULE-X match destination-address any
    set security policies from-zone trust to-zone untrust policy RULE-X match application any
    set security policies from-zone trust to-zone untrust policy RULE-X then permit
    """
    # The evaluator says RULE-X (a default-deny-equivalent rule in P) should
    # match every one of these sessions, but every session was actually
    # logged against a rule name the evaluator never produces -- a stand-in
    # for an object-resolution bug or unmodelled clause. Agreement is 0%,
    # which must fail the 99% default gate regardless of sample size.
    candidates = [_candidate(sessions=200, logged_rules=["SOME-OTHER-RULE"])]
    report = evaluate_change_impact(
        device_name="vsrx-ci",
        provider="juniper",
        p_rules=_junos_rules(text_before),
        pprime_rules=_junos_rules(text_after),
        object_book=EMPTY_BOOK,
        candidates=candidates,
        window_since="2026-09-20T00:00:00",
        window_until="2026-10-03T00:00:00",
        delta_payload={"kind": "calibration-fail-test"},
    )
    calibration = report["calibration"]["trust->untrust"]
    assert calibration["status"] == "below_threshold"
    assert calibration["downgrade_reason"] == "unknown: model does not reproduce device behaviour"
    assert calibration["mismatch_examples"]

    [rule_x] = report["changed_rules"]
    classes = rule_x["classes"]
    assert set(classes) == {"indeterminate"}
    assert classes["indeterminate"]["sessions"] == 200
    _assert_honesty_contract(report)


def test_calibration_cutoff_applies_to_global_rule_zone_pairs_uniformly():
    """The calibration cutoff is one device-level value and must gate every
    zone-pair's sessions by the flow's *actual* zone pair -- a global rule's
    own context carries no real zone pair (`("any", "any")`) to key a
    per-zone-pair cutoff lookup off of, so a lookup keyed that way would miss
    every real flow and silently stop gating stale sessions out."""
    text_before = """
    set security policies global policy G match source-address any
    set security policies global policy G match destination-address any
    set security policies global policy G match application any
    set security policies global policy G then deny
    """
    text_after = """
    set security policies global policy G match source-address any
    set security policies global policy G match destination-address any
    set security policies global policy G match application any
    set security policies global policy G then permit
    """
    pre_cutoff = _candidate(
        src_ip="10.9.9.1",
        sessions=200,
        logged_rules=["G"],
        first_seen="2026-09-01T00:00:00",
        last_seen="2026-09-05T00:00:00",
    )
    post_cutoff = _candidate(
        src_ip="10.9.9.2",
        sessions=5,
        logged_rules=["G"],
        first_seen="2026-09-25T00:00:00",
        last_seen="2026-09-26T00:00:00",
    )
    report = evaluate_change_impact(
        device_name="vsrx-ci",
        provider="juniper",
        p_rules=_junos_rules(text_before),
        pprime_rules=_junos_rules(text_after),
        object_book=EMPTY_BOOK,
        candidates=[pre_cutoff, post_cutoff],
        window_since="2026-09-01T00:00:00",
        window_until="2026-10-03T00:00:00",
        delta_payload={"kind": "global-rule-cutoff-test"},
        cutoff="2026-09-20T00:00:00",
    )
    calibration = report["calibration"]["trust->untrust"]
    # Only the 5 post-cutoff sessions may count; that's below the 100-session
    # minimum, so the gate must still refuse to trust this zone-pair. Before
    # the fix, the cutoff was looked up by the rule's own zone pair
    # (`("any", "any")`), never a key the flow's actual `("trust",
    # "untrust")` zone pair would find, so it fell back to "no cutoff" and
    # all 205 sessions -- including the 200 stale ones -- were counted.
    assert calibration["status"] == "insufficient_sample"
    assert calibration["sample_sessions"] == 5


def test_calibration_gate_passes_below_minimum_sample():
    text_before = """
    set security policies from-zone trust to-zone untrust policy RULE-Y match source-address any
    set security policies from-zone trust to-zone untrust policy RULE-Y match destination-address any
    set security policies from-zone trust to-zone untrust policy RULE-Y match application any
    set security policies from-zone trust to-zone untrust policy RULE-Y then deny
    """
    text_after = """
    set security policies from-zone trust to-zone untrust policy RULE-Y match source-address any
    set security policies from-zone trust to-zone untrust policy RULE-Y match destination-address any
    set security policies from-zone trust to-zone untrust policy RULE-Y match application any
    set security policies from-zone trust to-zone untrust policy RULE-Y then permit
    """
    # Perfect agreement, but only 5 sessions -- under the 100-session minimum,
    # so the gate still refuses to trust the zone-pair.
    candidates = [_candidate(sessions=5, logged_rules=["RULE-Y"])]
    report = evaluate_change_impact(
        device_name="vsrx-ci",
        provider="juniper",
        p_rules=_junos_rules(text_before),
        pprime_rules=_junos_rules(text_after),
        object_book=EMPTY_BOOK,
        candidates=candidates,
        window_since="2026-09-20T00:00:00",
        window_until="2026-10-03T00:00:00",
        delta_payload={"kind": "calibration-sample-test"},
    )
    calibration = report["calibration"]["trust->untrust"]
    assert calibration["status"] == "insufficient_sample"
    [section] = report["changed_rules"]
    assert set(section["classes"]) == {"indeterminate"}


# ---------------------------------------------------------------------------
# Golden case 5: multi-rule change where two edits cancel out
# ---------------------------------------------------------------------------


def test_multi_rule_change_reports_per_rule_even_when_aggregate_cancels_out():
    text_before = """
    set security policies from-zone trust to-zone untrust policy OPEN-A match source-address any
    set security policies from-zone trust to-zone untrust policy OPEN-A match destination-address any
    set security policies from-zone trust to-zone untrust policy OPEN-A match application any
    set security policies from-zone trust to-zone untrust policy OPEN-A then deny
    set security policies from-zone trust to-zone untrust policy CLOSE-B match source-address any
    set security policies from-zone trust to-zone untrust policy CLOSE-B match destination-address any
    set security policies from-zone trust to-zone untrust policy CLOSE-B match application any
    set security policies from-zone trust to-zone untrust policy CLOSE-B then permit
    """
    # OPEN-A: deny -> permit (opens). CLOSE-B: permit -> deny (breaks). Both
    # rules are unreachable behind each other in a real rulebase, but the
    # report must still show BOTH per-rule effects, not a net "nothing
    # changed" -- the doc is explicit that two changes can cancel out and
    # that this must not be hidden (doc §3).
    text_after = """
    set security policies from-zone trust to-zone untrust policy OPEN-A match source-address any
    set security policies from-zone trust to-zone untrust policy OPEN-A match destination-address any
    set security policies from-zone trust to-zone untrust policy OPEN-A match application any
    set security policies from-zone trust to-zone untrust policy OPEN-A then permit
    set security policies from-zone trust to-zone untrust policy CLOSE-B match source-address any
    set security policies from-zone trust to-zone untrust policy CLOSE-B match destination-address any
    set security policies from-zone trust to-zone untrust policy CLOSE-B match application any
    set security policies from-zone trust to-zone untrust policy CLOSE-B then deny
    """
    candidates = [
        _candidate(src_ip="10.9.9.1", sessions=150, logged_rules=["OPEN-A"]),
    ]
    report = evaluate_change_impact(
        device_name="vsrx-ci",
        provider="juniper",
        p_rules=_junos_rules(text_before),
        pprime_rules=_junos_rules(text_after),
        object_book=EMPTY_BOOK,
        candidates=candidates,
        window_since="2026-09-20T00:00:00",
        window_until="2026-10-03T00:00:00",
        delta_payload={"kind": "cancel-out-test"},
        cutoff=None,
        calibration_min_sample=1,
    )
    by_name = {s["rule_name"]: s for s in report["changed_rules"]}
    assert set(by_name) == {"OPEN-A", "CLOSE-B"}
    # OPEN-A: the one candidate tuple sees deny (P, OPEN-A unreachable? no --
    # OPEN-A is first in context order so it IS reachable) -> permit (P').
    open_a_classes = by_name["OPEN-A"]["classes"]
    assert "verdict_change_opens" in open_a_classes
    assert open_a_classes["verdict_change_opens"]["sessions"] == 150
    # CLOSE-B never sees traffic in this fixture (OPEN-A always matches
    # first), so its report is the explicit "no sessions observed" wording,
    # not a fabricated zero.
    assert by_name["CLOSE-B"]["result"] == NO_SESSIONS_OBSERVED
    _assert_honesty_contract(report)


def test_identical_rulebases_report_no_rule_change_without_candidate_io():
    """When P and P' have no changed rule names at all, the pipeline must
    say so explicitly (`NO_RULE_CHANGE`) rather than proceed as if there were
    a real (empty) change set -- the caller (services/mcp-query's tool
    wrapper) relies on this to skip an unscoped candidate pull entirely."""
    text = """
    set security policies from-zone trust to-zone untrust policy RULE-A match source-address any
    set security policies from-zone trust to-zone untrust policy RULE-A match destination-address any
    set security policies from-zone trust to-zone untrust policy RULE-A match application any
    set security policies from-zone trust to-zone untrust policy RULE-A then deny
    """
    rules = _junos_rules(text)
    report = evaluate_change_impact(
        device_name="vsrx-ci",
        provider="juniper",
        p_rules=rules,
        pprime_rules=rules,
        object_book=EMPTY_BOOK,
        candidates=[_candidate(sessions=150, logged_rules=["RULE-A"])],
        window_since="2026-09-20T00:00:00",
        window_until="2026-10-03T00:00:00",
        delta_payload={"kind": "no-op-test"},
        cutoff=None,
    )
    assert report["changed_rules"] == []
    assert report["note"] == NO_RULE_CHANGE
    _assert_honesty_contract(report)


# ---------------------------------------------------------------------------
# F1 regression: a JSON-delta `move` must be visible to the diff and the
# evaluator. `apply_delta` used to reorder the Python list but never touch
# the stale `position` field those rules carried, so `diff_rulebases`
# (which compares `position`, not list order) saw no reorder at all and the
# config-only pre-check stamped the move CONFIG_ONLY_NO_IMPACT even though
# it silently blocks every session that used to match the allowed rule.
# ---------------------------------------------------------------------------


def test_json_delta_move_to_front_is_reported_not_hidden():
    p_rules = [
        _json_rule("ALLOW-ANY", "allow", 0),
        _json_rule("DENY-ALL", "deny", 1),
    ]
    delta = parse_json_delta(
        [{"op": "move", "rule_name": "DENY-ALL", "before": "ALLOW-ANY"}], "juniper"
    )
    pprime_rules = apply_delta(p_rules, delta)
    assert [r["rule_name"] for r in pprime_rules] == ["DENY-ALL", "ALLOW-ANY"]

    candidates = [_candidate(sessions=500, logged_rules=["ALLOW-ANY"])]
    report = evaluate_change_impact(
        device_name="vsrx-ci",
        provider="juniper",
        p_rules=p_rules,
        pprime_rules=pprime_rules,
        object_book=EMPTY_BOOK,
        candidates=candidates,
        window_since="2026-09-20T00:00:00",
        window_until="2026-10-03T00:00:00",
        delta_payload={"kind": "f1-json-move-regression"},
        calibration_min_sample=1,
    )
    by_name = {s["rule_name"]: s for s in report["changed_rules"]}
    assert set(by_name) == {"ALLOW-ANY", "DENY-ALL"}
    for section in by_name.values():
        assert section.get("result") != CONFIG_ONLY_NO_IMPACT, (
            "a move that reorders a deny ahead of an allow must never report as provably no impact"
        )
    # DENY-ALL now matches first on this zone-pair and blocks the 500
    # sessions that used to be permitted by ALLOW-ANY -- the real,
    # unhidden verdict change.
    assert "verdict_change_breaks" in by_name["DENY-ALL"]["classes"]
    assert by_name["DENY-ALL"]["classes"]["verdict_change_breaks"]["sessions"] == 500
    _assert_honesty_contract(report)


def test_json_delta_add_after_lands_at_its_list_position_not_caller_default():
    """F1 regression, 'add' side: a new rule's `position` must come from
    where `apply_delta` actually inserted it in the list, not from whatever
    the caller's rule dict said (or didn't say -- a missing key used to
    default to 0, i.e. "evaluated first", no matter what 'before'/'after'
    requested)."""
    p_rules = [
        _json_rule("A", "allow", 0),
        _json_rule("B", "deny", 1),
        _json_rule("C", "allow", 2),
    ]
    new_rule = {
        "rule_name": "NEW",
        "action": "deny",
        "from_zone": ["trust"],
        "to_zone": ["untrust"],
    }
    delta = parse_json_delta([{"op": "add", "rule": new_rule, "after": "B"}], "juniper")
    pprime_rules = apply_delta(p_rules, delta)
    assert [r["rule_name"] for r in pprime_rules] == ["A", "B", "NEW", "C"]

    compiled = compile_rulebase(pprime_rules, EMPTY_BOOK)
    positions = {c.rule_name: c.position for c in compiled}
    # Before the fix, NEW's position defaulted to 0 and tied with A's,
    # sorting NEW ahead of B -- exactly the "evaluated first regardless of
    # before/after" bug the review called out.
    assert positions["A"] < positions["B"] < positions["NEW"] < positions["C"]


# ---------------------------------------------------------------------------
# Honesty-contract wording enforcement (acceptance criterion 2)
# ---------------------------------------------------------------------------

_ALLOWED_SAFE_PHRASES = (CONFIG_ONLY_NO_IMPACT,)
_FORBIDDEN_WORDS = re.compile(r"\bsafe\b|\bno impact\b", re.IGNORECASE)


def _assert_honesty_contract(report: dict) -> None:
    text = str(report)
    for phrase in _ALLOWED_SAFE_PHRASES:
        text = text.replace(phrase, "")
    assert not _FORBIDDEN_WORDS.search(text), (
        "report contains forbidden wording outside the one approved phrase: " + text
    )


@pytest.mark.parametrize(
    "report",
    [
        {"changed_rules": [{"rule_name": "X", "result": CONFIG_ONLY_NO_IMPACT}]},
    ],
)
def test_honesty_contract_allows_only_the_one_config_only_phrase(report):
    _assert_honesty_contract(report)


def test_honesty_contract_catches_forbidden_wording():
    with pytest.raises(AssertionError):
        _assert_honesty_contract({"summary": "this rule is safe to remove"})
    with pytest.raises(AssertionError):
        _assert_honesty_contract({"summary": "no impact detected"})
