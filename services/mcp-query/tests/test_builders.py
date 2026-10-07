# tests/test_builders.py
import pytest
from ssdf_mcp_query.builders import (
    build_query_flows,
    build_top_talkers,
    build_zone_matrix,
    FLOW_COLUMNS,
    BuilderError,
)


def test_query_flows_no_filters_has_window_and_limit():
    sql, params = build_query_flows(limit=100)
    assert "FROM ssdf.events" in sql
    assert "ORDER BY timestamp DESC" in sql
    assert "LIMIT 100" in sql
    assert "since" in params and "until" in params  # default window bound


def test_query_flows_filters_bind_params_not_interpolated():
    sql, params = build_query_flows(src_ip="10.64.0.1", action="flow_session_deny", dst_port=443)
    assert "10.64.0.1" not in sql  # value is bound, never inlined
    assert params["src_ip"] == "10.64.0.1"
    assert params["action"] == "flow_session_deny"
    assert params["dst_port"] == 443
    assert "{src_ip:String}" in sql
    assert "{dst_port:UInt16}" in sql


def test_query_flows_zone_matches_either_side():
    sql, _ = build_query_flows(zone="trust")
    assert "observer_ingress_zone" in sql and "observer_egress_zone" in sql


def test_query_flows_limit_clamped():
    sql, _ = build_query_flows(limit=10_000)
    assert "LIMIT 1000" in sql


def test_query_flows_selects_expected_columns():
    sql, _ = build_query_flows()
    for col in FLOW_COLUMNS:
        assert col in sql


def test_top_talkers_by_bytes_src():
    sql, params = build_top_talkers(by="bytes", side="src", limit=5)
    assert "source_ip" in sql
    assert "sum(network_bytes)" in sql
    assert "LIMIT 5" in sql


def test_top_talkers_by_flows_dst():
    sql, _ = build_top_talkers(by="flows", side="dst")
    assert "destination_ip" in sql
    assert "count()" in sql


def test_top_talkers_invalid_args_raise():
    with pytest.raises(BuilderError):
        build_top_talkers(by="nope", side="src")
    with pytest.raises(BuilderError):
        build_top_talkers(by="bytes", side="nope")


def test_zone_matrix_groups_by_zone_pair_and_observer():
    sql, params = build_zone_matrix(by="bytes")
    assert "FROM ssdf.events" in sql
    assert "observer_ingress_zone AS from_zone" in sql
    assert "observer_egress_zone AS to_zone" in sql
    assert "observer_hostname AS observer" in sql
    assert "GROUP BY from_zone, to_zone, observer" in sql
    assert "ORDER BY bytes DESC" in sql
    assert "LIMIT 501" in sql  # one extra row to detect truncation
    assert "since" in params and "until" in params  # default window bound


def test_zone_matrix_excludes_rows_without_zones():
    # zone columns are LowCardinality(String), not Nullable: "no zone" is ''
    sql, _ = build_zone_matrix()
    assert "observer_ingress_zone != ''" in sql
    assert "observer_egress_zone != ''" in sql


def test_zone_matrix_orders_by_flows():
    sql, _ = build_zone_matrix(by="flows")
    assert "ORDER BY flows DESC" in sql


def test_zone_matrix_observer_is_bound_not_inlined():
    sql, params = build_zone_matrix(observer="srx-edge-1")
    assert "srx-edge-1" not in sql
    assert params["observer"] == "srx-edge-1"
    assert "observer_hostname = {observer:String}" in sql


def test_zone_matrix_without_observer_has_no_observer_param():
    sql, params = build_zone_matrix()
    assert "observer" not in params
    assert "{observer:String}" not in sql


def test_zone_matrix_rejects_bad_by():
    with pytest.raises(BuilderError):
        build_zone_matrix(by="packets")


def test_zone_matrix_clamps_limit():
    sql, _ = build_zone_matrix(limit=10_000)
    assert "LIMIT 501" in sql
    sql, _ = build_zone_matrix(limit=0)
    assert "LIMIT 2" in sql
