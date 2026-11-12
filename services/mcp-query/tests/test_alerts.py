# tests/test_alerts.py
import os

os.environ.setdefault("CH_PASSWORD", "x")
os.environ.setdefault("MCP_AUTH_TOKEN", "t")

from ssdf_mcp_query.alerts import (
    ALERT_GATE_SQL,
    MAX_COUNT_GROUPS,
    SEVERITY_NUM_SQL,
    SIGNATURE_SQL,
    AlertTools,
    build_alert_counts_sql,
    build_recent_alerts_sql,
    normalize_severity,
)


def test_suricata_severity_inverted():
    assert normalize_severity("unifi", "alert", {"unifi.ips.severity": "1"}) == ("critical", 4)
    assert normalize_severity("unifi", "alert", {"unifi.ips.severity": "2"}) == ("high", 3)
    assert normalize_severity("unifi", "alert", {"unifi.ips.severity": "3"}) == ("medium", 2)


def test_pan_threat_severity_strings():
    # PAN severity key: panw.panos.severity (pinned from vector.toml line 342)
    assert normalize_severity("paloalto", "alert", {"panw.panos.severity": "critical"}) == (
        "critical",
        4,
    )
    assert normalize_severity("paloalto", "alert", {"panw.panos.severity": "informational"}) == (
        "low",
        1,
    )


def test_syslog_numeric_severity():
    assert normalize_severity("juniper", "event", {"syslog.severity": "2"}) == ("critical", 4)
    assert normalize_severity("juniper", "event", {"syslog.severity": "4"}) == ("medium", 2)


def test_non_alert_row_is_none():
    assert normalize_severity("proxmox", "event", {}) is None


def test_sql_filters_min_severity_and_providers():
    sql, params = build_recent_alerts_sql(
        since="now-24h", min_severity="high", providers="unifi,paloalto", limit=10
    )
    assert "LIMIT" in sql and params["limit"] == 10
    assert "event_provider IN" in sql
    # the floor is in the WHERE, so rows below it cannot use up the LIMIT
    assert params["floor"] == 3
    where = sql.split("WHERE", 1)[1].split("ORDER BY", 1)[0]
    assert ">= %(floor)s" in where


def test_sql_selects_pan_threat_via_ext_key():
    """PAN THREAT rows keep event_kind='event', so WHERE must gate on ext key."""
    sql, _ = build_recent_alerts_sql(since="now-1h", min_severity="high", providers="", limit=10)
    assert "ext['panw.panos.severity'] != ''" in sql


def test_recent_alerts_includes_pan_threat_row():
    """End-to-end: a PAN THREAT row (event_kind='event') must land in results."""
    from ssdf_mcp_query.alerts import AlertTools

    # Fake CH runner returning one PAN THREAT row
    class FakeCH:
        def run(self, sql, params):
            return {
                "columns": [
                    "event_id",
                    "timestamp",
                    "event_provider",
                    "event_kind",
                    "rule_name",
                    "source_ip",
                    "source_port",
                    "destination_ip",
                    "destination_port",
                    "observer_hostname",
                    "observer_ingress_zone",
                    "observer_egress_zone",
                    "ext",
                ],
                "rows": [
                    {
                        "event_id": "abc123",
                        "timestamp": "2026-07-09T12:00:00+00:00",
                        "event_provider": "paloalto",
                        "event_kind": "event",  # PAN THREAT logs keep event_kind="event"
                        "rule_name": "test-rule",
                        "signature": "test-rule",
                        "source_ip": "10.65.1.1",
                        "source_port": 12345,
                        "destination_ip": "10.66.2.2",
                        "destination_port": 443,
                        "observer_hostname": "panosvm",
                        "observer_ingress_zone": "trust",
                        "observer_egress_zone": "untrust",
                        "ext": {"panw.panos.severity": "critical", "panw.panos.threat_id": "30001"},
                    }
                ],
                "row_count": 1,
            }

    tools = AlertTools(FakeCH())
    result = tools.recent_alerts(since="now-1h", min_severity="high", providers="", limit=10)

    assert result["row_count"] == 1
    row = result["rows"][0]
    assert row["severity"] == "critical"
    assert row["severity_num"] == 4
    assert row["provider"] == "paloalto"
    # signature is log-derived (MEC-568): distinct typed shape, not a bare str.
    assert row["signature"] == {"value": "test-rule", "truncated": False, "untrusted": True}
    assert row["ext_subset"]["panw.panos.severity"] == {
        "value": "critical",
        "truncated": False,
        "untrusted": True,
    }


def test_recent_alerts_signature_truncated_not_silently_dropped():
    """An oversized log-derived signature is capped with an explicit truncated flag."""
    from ssdf_mcp_query.alerts import AlertTools
    from ssdf_mcp_query.untrusted_text import DEFAULT_MAX_LEN

    oversized_signature = "X" * (DEFAULT_MAX_LEN + 50)

    class FakeCH:
        def run(self, sql, params):
            return {
                "columns": [],
                "rows": [
                    {
                        "event_id": "abc123",
                        "timestamp": "2026-07-09T12:00:00+00:00",
                        "event_provider": "unifi",
                        "event_kind": "alert",
                        "rule_name": "",
                        "signature": oversized_signature,
                        "source_ip": "10.65.1.1",
                        "source_port": 12345,
                        "destination_ip": "10.66.2.2",
                        "destination_port": 443,
                        "observer_hostname": "unifi-gw",
                        "observer_ingress_zone": "lan",
                        "observer_egress_zone": "wan",
                        "ext": {
                            "unifi.ips.signature": oversized_signature,
                            "unifi.ips.severity": "1",
                        },
                    }
                ],
                "row_count": 1,
            }

    tools = AlertTools(FakeCH())
    result = tools.recent_alerts(since="now-1h", min_severity="high", providers="", limit=10)
    row = result["rows"][0]
    assert row["signature"]["truncated"] is True
    assert len(row["signature"]["value"]) == DEFAULT_MAX_LEN
    assert row["ext_subset"]["unifi.ips.signature"]["truncated"] is True


def test_recent_alerts_is_registered_sovereign(monkeypatch):
    """recent_alerts must be registered on sovereign tier only."""
    import asyncio
    import ssdf_mcp_query.server as server

    class _Dummy:
        def __init__(self, *a, **k):
            pass

    monkeypatch.setattr(server, "ClickHouseClient", _Dummy)
    app = server.build_app()
    tools = asyncio.run(app.list_tools())
    tool_names = {t.name for t in tools}
    assert "recent_alerts" in tool_names


def test_recent_alerts_not_registered_public(monkeypatch):
    """recent_alerts must NEVER appear on the public tier (security_log class)."""
    import asyncio
    import ssdf_mcp_query.server as server

    class _Dummy:
        def __init__(self, *a, **k):
            pass

    monkeypatch.setattr(server, "ClickHouseClient", _Dummy)
    app = server.build_app(tier="public")
    tools = asyncio.run(app.list_tools())
    tool_names = {t.name for t in tools}
    assert "recent_alerts" not in tool_names


def test_recent_alerts_with_all_defaults():
    """Default since must parse cleanly (was '24 hours ago', crashes with parse_time)."""
    from ssdf_mcp_query.alerts import AlertTools

    # Fake CH runner that captures the query params
    class FakeCH:
        def run(self, sql, params):
            # If parse_time crashes on the default, we never get here
            assert "since" in params  # parse_time succeeded
            return {"columns": [], "rows": [], "row_count": 0}

    tools = AlertTools(FakeCH())
    # Call with ALL DEFAULTS — since default flows through build_recent_alerts_sql/parse_time
    result = tools.recent_alerts()
    assert result["row_count"] == 0  # no rows, but no crash


# --- Regression: recent_alerts window bound must not ride the String alias ---
#
# The SELECT aliases `toString(timestamp) AS timestamp`. An unqualified
# `timestamp` in WHERE/ORDER BY binds to that alias, making the window a lexical
# string compare. It agreed only because the bound is a datetime rendered in the
# same layout toString() emits — a coincidence, not a guarantee. Qualifying
# removes the dependency. Same defect class as build_subgraph_sql.


def test_recent_alerts_window_uses_the_datetime_column_not_the_alias():
    sql, _ = build_recent_alerts_sql(since="now-1h", min_severity="high", providers="", limit=10)
    assert "events.timestamp >= %(since)s" in sql
    assert "AND timestamp >=" not in sql
    assert not sql.split("WHERE", 1)[1].startswith(" timestamp >=")


def test_recent_alerts_ordering_uses_the_datetime_column_not_the_alias():
    sql, _ = build_recent_alerts_sql(since="now-1h", min_severity="high", providers="", limit=10)
    assert "ORDER BY events.timestamp DESC" in sql


# --- Regression: the severity floor used to run in Python AFTER the LIMIT, so the
# newest rows below it (PAN-OS informational system logs) filled the LIMIT and the
# tool returned nothing while 74 medium/high PAN alerts sat in the window. ---


def test_unknown_min_severity_floors_at_high():
    _, params = build_recent_alerts_sql(
        since="now-1h", min_severity="bogus", providers="", limit=10
    )
    assert params["floor"] == 3


def test_junos_screen_signature_is_the_event_action_not_na():
    """RT_SCREEN rows have rule_name 'N/A'; the screen name is in event_action."""
    from ssdf_mcp_query.alerts import AlertTools

    class FakeCH:
        def run(self, sql, params):
            assert "event_action" in sql.split("FROM", 1)[0]
            return {
                "columns": [],
                "rows": [
                    {
                        "event_id": "s1",
                        "timestamp": "2026-11-12T16:56:46+00:00",
                        "event_provider": "juniper",
                        "event_kind": "alert",
                        "event_action": "screen_icmp_flood",
                        "rule_name": "N/A",
                        "signature": "screen_icmp_flood",
                        "observer_hostname": "srx-test",
                        "ext": {},
                    }
                ],
                "row_count": 1,
            }

    result = AlertTools(FakeCH()).recent_alerts(since="now-1h", min_severity="medium")
    assert result["rows"][0]["signature"]["value"] == "screen_icmp_flood"
    assert result["rows"][0]["severity"] == "medium"


# --- UniFi controller-event severity (CEF 0-10) ---


def test_unifi_event_severity_bands():
    bands = {
        "0": ("low", 1),
        "3": ("low", 1),
        "4": ("medium", 2),
        "6": ("medium", 2),
        "7": ("high", 3),
        "8": ("high", 3),
        "9": ("critical", 4),
        "10": ("critical", 4),
    }
    for sev, expected in bands.items():
        assert normalize_severity("unifi", "alert", {"unifi.event.severity": sev}) == expected


def test_ips_severity_outranks_unifi_event_severity():
    ext = {"unifi.ips.severity": "1", "unifi.event.severity": "3"}
    assert normalize_severity("unifi", "alert", ext) == ("critical", 4)


def test_sql_checks_severity_keys_in_the_order_normalize_severity_does():
    import re

    keys = re.findall(r"ext\['([a-z.]+)'\] != ''", SEVERITY_NUM_SQL)
    assert keys == [
        "unifi.ips.severity",
        "panw.panos.severity",
        "unifi.event.severity",
        "syslog.severity",
    ]


# (ext, expected severity_num) -- the SQL expression is pinned to the same table
# by the sql-contract job (test_sql_contract.py::test_severity_sql_matches_python_table).
SEVERITY_PARITY_CASES = [
    ({"unifi.ips.severity": "1"}, 4),
    ({"unifi.ips.severity": "2"}, 3),
    ({"unifi.ips.severity": "3"}, 2),
    ({"panw.panos.severity": "Critical"}, 4),
    ({"panw.panos.severity": "high"}, 3),
    ({"panw.panos.severity": "medium"}, 2),
    ({"panw.panos.severity": "low"}, 1),
    ({"panw.panos.severity": "informational"}, 1),
    ({"panw.panos.severity": "weird"}, 2),
    ({"unifi.event.severity": "0"}, 1),
    ({"unifi.event.severity": "3"}, 1),
    ({"unifi.event.severity": "4"}, 2),
    ({"unifi.event.severity": "6"}, 2),
    ({"unifi.event.severity": "7"}, 3),
    ({"unifi.event.severity": "8"}, 3),
    ({"unifi.event.severity": "9"}, 4),
    ({"unifi.event.severity": "10"}, 4),
    ({"unifi.event.severity": "abc"}, 1),
    ({"unifi.event.severity": "5", "syslog.severity": "3"}, 2),
    ({"syslog.severity": "2"}, 4),
    ({"syslog.severity": "3"}, 3),
    ({"syslog.severity": "4"}, 2),
    ({"syslog.severity": "6"}, 1),
    ({"syslog.severity": ""}, 2),
    ({"unifi.event.severity": "", "syslog.severity": "3"}, 3),
    ({}, 2),
]


def test_normalize_severity_matches_the_parity_table():
    for ext, expected in SEVERITY_PARITY_CASES:
        assert normalize_severity("x", "alert", ext)[1] == expected, ext


# --- alert_counts ---


def test_alert_counts_uses_the_same_gate_severity_and_signature_expressions():
    counts_sql, counts_params = build_alert_counts_sql("now-1h", "medium", "unifi")
    recent_sql, recent_params = build_recent_alerts_sql("now-1h", "medium", "unifi", 10)
    for shared in (ALERT_GATE_SQL, SEVERITY_NUM_SQL + " >= %(floor)s", SIGNATURE_SQL):
        assert shared in counts_sql
        assert shared in recent_sql
    assert counts_params["floor"] == recent_params["floor"] == 2
    assert counts_params["providers"] == ("unifi",)


def test_alert_counts_sql_groups_and_orders_with_the_floor_in_where():
    sql, params = build_alert_counts_sql("now-24h", "low", "")
    where = sql.split("WHERE", 1)[1].split("GROUP BY", 1)[0]
    assert ">= %(floor)s" in where
    assert "GROUP BY provider, observer, signature, severity_num" in sql
    assert "ORDER BY severity_num DESC, n DESC" in sql
    assert params["floor"] == 1
    assert params["max_groups"] == MAX_COUNT_GROUPS + 1
    assert "providers" not in params


def test_signature_sql_falls_back_rule_then_action_then_kind():
    # branch order is the contract: IPS signature, rule name, event action, event kind
    positions = [
        SIGNATURE_SQL.index(token)
        for token in (
            "unifi.ips.signature",
            "rule_name NOT IN ('', 'N/A')",
            "event_action",
            "event_kind",
        )
    ]
    assert positions == sorted(positions)


def _counts_row(signature="wan_down", severity_num=3, n=5, observer="unifi-gw"):
    return {
        "provider": "unifi",
        "observer": observer,
        "signature": signature,
        "severity_num": severity_num,
        "n": n,
        "first_seen": "2026-11-12 01:00:00",
        "last_seen": "2026-11-12 02:00:00",
    }


def test_alert_counts_shapes_and_wraps_rows():
    class FakeCH:
        def run(self, sql, params):
            return {"rows": [_counts_row(signature="x" * 5000)], "row_count": 1}

    result = AlertTools(FakeCH()).alert_counts()
    row = result["rows"][0]
    assert row["severity"] == "high" and row["count"] == 5
    assert row["signature"]["untrusted"] is True and row["signature"]["truncated"] is True
    assert row["observer"] == {"value": "unifi-gw", "truncated": False, "untrusted": True}
    assert row["provider"] == "unifi"
    assert result["truncated"] is False and result["row_count"] == 1


def test_alert_counts_truncated_when_more_than_the_cap():
    class FakeCH:
        def run(self, sql, params):
            rows = [_counts_row(signature=f"sig{i}") for i in range(MAX_COUNT_GROUPS + 1)]
            return {"rows": rows, "row_count": len(rows)}

    result = AlertTools(FakeCH()).alert_counts()
    assert result["truncated"] is True
    assert result["row_count"] == MAX_COUNT_GROUPS


def _tool_names(monkeypatch, tier):
    import asyncio
    import ssdf_mcp_query.server as server

    class _Dummy:
        def __init__(self, *a, **k):
            pass

    monkeypatch.setattr(server, "ClickHouseClient", _Dummy)
    return {t.name for t in asyncio.run(server.build_app(tier=tier).list_tools())}


def test_alert_counts_registered_sovereign_not_public(monkeypatch):
    assert "alert_counts" in _tool_names(monkeypatch, "sovereign")
    assert "alert_counts" not in _tool_names(monkeypatch, "public")
