# tests/test_alerts.py
import os

os.environ.setdefault("CH_PASSWORD", "x")
os.environ.setdefault("MCP_AUTH_TOKEN", "t")

from ssdf_mcp_query.alerts import normalize_severity, build_recent_alerts_sql


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
