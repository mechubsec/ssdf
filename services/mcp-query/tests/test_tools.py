# tests/test_tools.py
import re

from ssdf_mcp_query.tools import Tools


class FakeClient:
    def __init__(self, rows=None, columns=None, raise_exc=None):
        self._rows = rows or []
        self._columns = columns or []
        self._raise = raise_exc
        self.last_sql = None
        self.last_params = None

    def run(self, sql, params=None):
        self.last_sql = sql
        self.last_params = params
        if self._raise:
            raise self._raise
        return {"columns": self._columns, "rows": self._rows, "row_count": len(self._rows)}


def test_query_flows_returns_rows_and_metadata():
    fake = FakeClient(rows=[{"source_ip": "10.64.0.1"}], columns=["source_ip"])
    tools = Tools(fake, max_rows=1000)
    out = tools.query_flows(action="flow_session_deny", since="now-1h")
    assert out["row_count"] == 1
    assert out["rows"][0]["source_ip"] == "10.64.0.1"
    assert out["truncated"] is False
    assert "elapsed_ms" in out
    assert fake.last_params["action"] == "flow_session_deny"


def test_query_flows_wraps_log_derived_free_text_columns():
    fake = FakeClient(
        rows=[
            {
                "source_ip": "10.64.0.1",
                "rule_name": "allow-web",
                "user_name": "alice",
                "observer_ingress_zone": "untrust",
                "observer_egress_zone": "trust",
            }
        ],
        columns=[
            "source_ip",
            "rule_name",
            "user_name",
            "observer_ingress_zone",
            "observer_egress_zone",
        ],
    )
    tools = Tools(fake, max_rows=1000)
    out = tools.query_flows(action="flow_session_deny", since="now-1h")
    row = out["rows"][0]
    # Numeric/IP columns pass through untouched.
    assert row["source_ip"] == "10.64.0.1"
    # Log-echoed free-text columns carry the UntrustedText response shape.
    assert row["rule_name"] == {"value": "allow-web", "truncated": False, "untrusted": True}
    assert row["user_name"] == {"value": "alice", "truncated": False, "untrusted": True}
    assert row["observer_ingress_zone"] == {
        "value": "untrust",
        "truncated": False,
        "untrusted": True,
    }
    assert row["observer_egress_zone"] == {"value": "trust", "truncated": False, "untrusted": True}


def test_query_flows_wrapped_column_reports_truncation():
    long_name = "x" * 600
    fake = FakeClient(rows=[{"rule_name": long_name}], columns=["rule_name"])
    tools = Tools(fake, max_rows=1000)
    out = tools.query_flows()
    wrapped = out["rows"][0]["rule_name"]
    assert wrapped["truncated"] is True
    assert len(wrapped["value"]) == 512


def test_query_flows_truncated_flag():
    rows = [{"x": i} for i in range(1000)]
    tools = Tools(FakeClient(rows=rows, columns=["x"]), max_rows=1000)
    out = tools.query_flows(limit=1000)
    assert out["truncated"] is True  # hit the cap


def test_run_sql_rejected_returns_validation_error():
    tools = Tools(FakeClient(), max_rows=1000)
    out = tools.run_sql("DROP TABLE ssdf.events")
    assert out["error"] == "validation"


def test_run_sql_allowed_executes_guarded_sql():
    fake = FakeClient(rows=[{"n": 1}], columns=["n"])
    tools = Tools(fake, max_rows=1000)
    out = tools.run_sql("SELECT count() AS n FROM ssdf.events")
    assert out["row_count"] == 1
    assert "limit" in fake.last_sql.lower()  # guard injected a LIMIT


def test_upstream_error_is_caught():
    tools = Tools(FakeClient(raise_exc=RuntimeError("ch down")), max_rows=1000)
    out = tools.query_flows()
    assert out["error"] == "upstream"


def test_top_talkers_invalid_arg_is_validation_error():
    tools = Tools(FakeClient(), max_rows=1000)
    out = tools.top_talkers(by="bogus")
    assert out["error"] == "validation"


def test_zone_matrix_invalid_arg_is_validation_error():
    tools = Tools(FakeClient(), max_rows=1000)
    out = tools.zone_matrix(by="packets")
    assert out["error"] == "validation"


def test_zone_matrix_bad_time_is_validation_error():
    tools = Tools(FakeClient(), max_rows=1000)
    assert tools.zone_matrix(since="not-a-time")["error"] == "validation"


def _zone_rows(count):
    return [
        {
            "from_zone": f"z{i}",
            "to_zone": "untrust",
            "observer": "srx1",
            "bytes": 100 - i,
            "flows": 1,
        }
        for i in range(count)
    ]


def test_zone_matrix_reports_truncation_and_drops_probe_row():
    fake = FakeClient(
        rows=_zone_rows(3), columns=["from_zone", "to_zone", "observer", "bytes", "flows"]
    )
    out = Tools(fake, max_rows=1000).zone_matrix(limit=2)
    assert out["truncated"] is True
    assert out["row_count"] == 2
    assert [r["from_zone"] for r in out["rows"]] == ["z0", "z1"]
    assert "LIMIT 3" in fake.last_sql


def test_zone_matrix_not_truncated_when_rows_fit():
    fake = FakeClient(rows=_zone_rows(2), columns=["from_zone"])
    out = Tools(fake, max_rows=1000).zone_matrix(limit=2)
    assert out["truncated"] is False
    assert out["row_count"] == 2
    assert len(out["rows"]) == 2
    assert "elapsed_ms" in out and out["columns"] == ["from_zone"]


def test_zone_matrix_upstream_error_passes_through():
    out = Tools(FakeClient(raise_exc=RuntimeError("ch down")), max_rows=1000).zone_matrix()
    assert out["error"] == "upstream"


class _BoomClient:
    def run(self, sql, params=None):
        raise RuntimeError("CH internal: column observer_hostname on host 198.51.100.151")


def test_safe_execute_scrubs_upstream_detail():
    out = Tools(_BoomClient()).query_flows(dst_port=443)
    assert out["error"] == "upstream"
    assert out["detail"] == "query failed"
    assert re.fullmatch(r"[0-9a-f]{32}", out["correlation_id"])
    blob = str(out)
    assert "198.51.100.151" not in blob
    assert "observer_hostname" not in blob


def test_describe_schema_scrubs_upstream_detail():
    out = Tools(_BoomClient()).describe_schema()
    assert out["error"] == "upstream"
    assert out["detail"] == "query failed"
    assert re.fullmatch(r"[0-9a-f]{32}", out["correlation_id"])
    assert "198.51.100.151" not in str(out)


def test_validation_error_detail_is_preserved():
    out = Tools(_BoomClient()).query_flows(since="not-a-time")
    assert out["error"] == "validation"
    assert out["detail"] != "query failed"
    assert "correlation_id" not in out
