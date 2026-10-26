# tests/test_builders.py
import pytest
from ssdf_mcp_query.builders import (
    HOST_LOG_PATTERNS_MAX_LIMIT,
    _HOST_LOG_NORMALIZERS,
    _ch_literal,
    build_host_log_patterns,
    build_host_log_sources,
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
    assert "ORDER BY bytes DESC, from_zone, to_zone, observer LIMIT 501" in sql
    assert "LIMIT 501" in sql  # one extra row to detect truncation
    assert "since" in params and "until" in params  # default window bound


def test_zone_matrix_excludes_rows_without_zones():
    # zone columns are LowCardinality(String), not Nullable: "no zone" is ''
    sql, _ = build_zone_matrix()
    assert "observer_ingress_zone != ''" in sql
    assert "observer_egress_zone != ''" in sql


def test_zone_matrix_scopes_to_flow_events():
    sql, _ = build_zone_matrix()
    assert "event_action LIKE 'flow_%'" in sql


def test_zone_matrix_bytes_is_null_safe():
    # network_bytes is Nullable(UInt64): an all-NULL group must sum to 0, not NULL
    sql, _ = build_zone_matrix()
    assert "sum(ifNull(network_bytes, 0)) AS bytes" in sql


def test_zone_matrix_orders_by_flows():
    sql, _ = build_zone_matrix(by="flows")
    assert "ORDER BY flows DESC, from_zone, to_zone, observer LIMIT 501" in sql


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


def test_host_log_patterns_normalizes_in_contract_order():
    sql, _ = build_host_log_patterns()
    assert [rep for _, rep in _HOST_LOG_NORMALIZERS] == [
        "<uuid>", "<ip>", r"\1<ipv-six>", "<hex>", "<n>", " ",
    ]  # fmt: skip
    # each step wraps the previous one, so its arguments read left to right in order
    positions = [
        sql.index(f"{_ch_literal(rx)}, {_ch_literal(rep)})") for rx, rep in _HOST_LOG_NORMALIZERS
    ]
    assert positions == sorted(positions)
    assert "'\\\\d+', '<n>'" in sql  # backslashes doubled for the ClickHouse literal
    assert "'\\\\1<ipv-six>'" in sql
    assert "replaceAll(" in sql and "'<ipv-six>', '<ip6>')" in sql
    assert "substringUTF8(trimBoth(replaceAll(" in sql and ", 1, 300)" in sql


def test_host_log_patterns_kind_and_severity_filter():
    sql, params = build_host_log_patterns(min_severity=5)
    assert "systemd-coredump%" in sql and "dumped core" in sql
    assert "Failed with result|entered failed state" in sql
    assert "kind != 'error' OR severity <= {min_severity:UInt8}" in sql
    assert params["min_severity"] == 5 and "{min_severity:UInt8}" in sql


def test_host_log_patterns_grouping_order_and_total():
    sql, params = build_host_log_patterns()
    assert "FROM ssdf.host_logs" in sql and "count() OVER () AS total_patterns" in sql
    assert "GROUP BY host, source, unit, kind, pattern" in sql
    assert (
        "ORDER BY occurrences DESC, last_seen DESC, host, source, unit, kind, pattern LIMIT 300"
        in sql
    )
    assert "since" in params and "until" in params and params["min_severity"] == 3


def test_host_log_patterns_validates_min_severity():
    for bad in (-1, 8, True, "3", 2.5, None):
        with pytest.raises(BuilderError):
            build_host_log_patterns(min_severity=bad)


def test_host_log_patterns_clamps_limit():
    assert HOST_LOG_PATTERNS_MAX_LIMIT == 500
    assert "LIMIT 500" in build_host_log_patterns(limit=10_000)[0]
    assert build_host_log_patterns(limit=0)[0].endswith("LIMIT 1")


def test_host_log_sources_sums_summing_merge_tree():
    sql, params = build_host_log_sources()
    assert params == {} and "FROM ssdf.host_log_senders" in sql
    assert "sumIf(lines, minute >= now() - INTERVAL 24 HOUR) AS lines_24h" in sql
    assert "minute >= now() - INTERVAL 7 DAY" in sql
