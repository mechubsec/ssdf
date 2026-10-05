"""build_candidate_pull_sql tests: the "any"-zone predicate and the limit+1
truncation-detection pull.
"""

from ssdf_mcp_query.change_impact_builders import DEFAULT_CANDIDATE_LIMIT, build_candidate_pull_sql


def test_pull_overfetches_by_one_row_to_detect_truncation():
    sql, _params = build_candidate_pull_sql(
        "vsrx-ci", [("trust", "untrust")], "2026-09-20T00:00:00", "2026-10-03T00:00:00", limit=5
    )
    assert f"LIMIT {5 + 1}" in sql
    assert "ORDER BY timestamp DESC" in sql


def test_any_ingress_zone_drops_that_side_of_the_predicate():
    """A rule with from_zone=any must not bind the literal string 'any' --
    that matches no real zone name, and the zone-pair must still be
    represented in the candidate set."""
    sql, params = build_candidate_pull_sql(
        "vsrx-ci", [("any", "untrust")], "2026-09-20T00:00:00", "2026-10-03T00:00:00"
    )
    assert "ingress_0" not in params
    assert "'any'" not in sql
    assert "observer_egress_zone = {egress_0:String}" in sql
    assert params["egress_0"] == "untrust"


def test_both_zones_any_drops_the_whole_pair_clause():
    sql, params = build_candidate_pull_sql(
        "vsrx-ci", [("any", "any")], "2026-09-20T00:00:00", "2026-10-03T00:00:00"
    )
    assert "'any'" not in sql
    assert not any(k.startswith(("ingress_", "egress_")) for k in params)


def test_default_limit_is_unchanged():
    assert DEFAULT_CANDIDATE_LIMIT == 50_000
