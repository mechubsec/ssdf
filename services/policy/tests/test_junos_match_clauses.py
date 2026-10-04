"""MEC-992: previously-dropped Junos match clauses must be parsed and flag
match_unknown, never silently treated as unmatched-clause == wildcard."""

from ssdf_policy.collectors.junos import parse_security_policies

BASE = (
    "set security policies from-zone trust to-zone untrust policy P1 "
    "match source-address any\n"
    "set security policies from-zone trust to-zone untrust policy P1 "
    "match destination-address any\n"
    "set security policies from-zone trust to-zone untrust policy P1 "
    "match application any\n"
    "set security policies from-zone trust to-zone untrust policy P1 then permit\n"
)


def _rule(extra_lines: str) -> dict:
    rules = parse_security_policies(BASE + extra_lines, "vSRX-test10", "2026-09-30T00:00:00")
    return next(r for r in rules if r["rule_name"] == "P1")


def test_plain_rule_is_not_flagged_unknown():
    rule = _rule("")
    assert rule["match_unknown"] is False


def test_source_address_excluded_is_deterministic_not_unknown():
    rule = _rule(
        "set security policies from-zone trust to-zone untrust policy P1 "
        "match source-address-excluded\n"
    )
    assert rule["source_address_excluded"] is True
    assert rule["match_unknown"] is False


def test_destination_address_excluded_is_deterministic_not_unknown():
    rule = _rule(
        "set security policies from-zone trust to-zone untrust policy P1 "
        "match destination-address-excluded\n"
    )
    assert rule["dest_address_excluded"] is True
    assert rule["match_unknown"] is False


def test_source_identity_is_parsed_and_flags_unknown():
    rule = _rule(
        "set security policies from-zone trust to-zone untrust policy P1 "
        "match source-identity ROLE-ENG\n"
    )
    assert rule["source_identity"] == ["ROLE-ENG"]
    assert rule["match_unknown"] is True


def test_dynamic_application_is_parsed_and_flags_unknown():
    rule = _rule(
        "set security policies from-zone trust to-zone untrust policy P1 "
        "match dynamic-application junos:FACEBOOK\n"
    )
    assert rule["dynamic_application"] == ["junos:FACEBOOK"]
    assert rule["match_unknown"] is True


def test_url_category_is_parsed_and_flags_unknown():
    rule = _rule(
        "set security policies from-zone trust to-zone untrust policy P1 "
        "match url-category Enhanced_Gambling\n"
    )
    assert rule["url_category"] == ["Enhanced_Gambling"]
    assert rule["match_unknown"] is True


def test_source_end_user_profile_is_parsed_and_flags_unknown():
    rule = _rule(
        "set security policies from-zone trust to-zone untrust policy P1 "
        "match source-end-user-profile WIN-DESKTOP\n"
    )
    assert rule["source_end_user_profile"] == ["WIN-DESKTOP"]
    assert rule["match_unknown"] is True


def test_scheduler_name_is_parsed_and_flags_unknown_without_scheduler_objects():
    # scheduler-name is a sibling of match/then under `policy NAME`, not a
    # match condition itself.
    rule = _rule(
        "set security policies from-zone trust to-zone untrust policy P1 "
        "scheduler-name BUSINESS-HOURS\n"
    )
    assert rule["scheduler_name"] == "BUSINESS-HOURS"
    assert rule["match_unknown"] is True


def test_unlisted_match_clause_flags_unknown_instead_of_vanishing():
    # MEC-992 review (F3): AC2 must be an allowlist, not an enumeration -- a
    # match keyword this collector has never heard of (source-l3-area here)
    # must never silently disappear and read as though it were absent.
    rule = _rule(
        "set security policies from-zone trust to-zone untrust policy P1 match source-l3-area A1\n"
    )
    assert rule["match_unknown"] is True
    assert rule["vendor_extras"]["unparsed_match"] == ["source-l3-area"]


def test_unrecognized_policy_level_keyword_flags_unknown():
    # Same class as the unlisted-match-clause case, but for a policy-level
    # keyword that isn't match/then/scheduler-name/description at all.
    rule = _rule("set security policies from-zone trust to-zone untrust policy P1 policy-rematch\n")
    assert rule["match_unknown"] is True
