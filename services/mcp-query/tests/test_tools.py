# tests/test_tools.py
import re

from ssdf_mcp_query.tools import Tools


class FakeClient:
    def __init__(self, rows=None, columns=None, raise_exc=None, queued_rows=None):
        # queued_rows: per-call row lists consumed in order (multi-query tools)
        self._queued = list(queued_rows or [])
        self.all_sql = []
        self._rows = rows or []
        self._columns = columns or []
        self._raise = raise_exc
        self.last_sql = None
        self.last_params = None

    def run(self, sql, params=None):
        self.last_sql = sql
        self.last_params = params
        self.all_sql.append(sql)
        if self._raise:
            raise self._raise
        if self._queued:
            queued = self._queued.pop(0)
            return {"columns": [], "rows": queued, "row_count": len(queued)}
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
    assert [r["from_zone"]["value"] for r in out["rows"]] == ["z0", "z1"]
    assert "LIMIT 3" in fake.last_sql


def test_zone_matrix_wraps_log_derived_columns_after_truncation():
    fake = FakeClient(rows=_zone_rows(3), columns=["from_zone"])
    out = Tools(fake, max_rows=1000).zone_matrix(limit=2)
    assert len(out["rows"]) == 2
    for row in out["rows"]:
        for col in ("from_zone", "to_zone", "observer"):
            assert isinstance(row[col], dict)
            assert row[col]["untrusted"] is True
            assert row[col]["truncated"] is False
        assert row["bytes"] in (100, 99) and row["flows"] == 1  # numerics stay raw
    assert out["rows"][0]["to_zone"]["value"] == "untrust"
    assert out["rows"][0]["observer"]["value"] == "srx1"


def test_zone_matrix_caps_oversized_zone_text():
    rows = [{"from_zone": "A" * 600, "to_zone": "b", "observer": "o", "bytes": 1, "flows": 1}]
    out = Tools(FakeClient(rows=rows), max_rows=1000).zone_matrix()
    assert out["rows"][0]["from_zone"]["truncated"] is True
    assert len(out["rows"][0]["from_zone"]["value"]) == 512


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


def _pattern_row(i=0, **over):
    row = {
        "host": "h1",
        "source": "journald",
        "unit": "sshd",
        "kind": "error",
        "pattern": f"fail <n> {i}",
        "worst_severity": 3,
        "occurrences": 10 - i,
        "first_seen": "2026-10-01T00:00:00+00:00",
        "last_seen": "2026-10-01T01:00:00+00:00",
        "sample": "fail 42",
        "total_patterns": 5,
    }
    return {**row, **over}


_SENDER = {"host": "h1", "source": "journald", "last_seen": "2026-10-01T01:00:00", "lines_24h": 7}


def test_host_log_patterns_reply_shape_and_wrapping():
    fake = FakeClient(queued_rows=[[_pattern_row(sample="x" * 600)], [dict(_SENDER)]])
    out = Tools(fake, max_rows=1000).host_log_patterns()
    assert len(fake.all_sql) == 2 and "host_log_senders" in fake.all_sql[1]
    row = out["patterns"][0]
    assert row["severity"] == 3 and row["count"] == 10 and row["kind"] == "error"
    assert row["source"] == "journald" and row["first_seen"].startswith("2026-10-01")
    for col in ("host", "unit", "pattern"):
        assert row[col]["untrusted"] is True and len(row[col]["value"]) <= 512
    assert row["sample"]["untrusted"] is True
    assert len(row["sample"]["value"]) == 500 and row["sample"]["truncated"] is True
    assert out["sources"][0]["host"]["value"] == "h1"
    assert out["sources"][0]["source"] == "journald" and out["sources"][0]["lines_24h"] == 7


def test_host_log_patterns_truncated_flag():
    rows = [_pattern_row(i) for i in range(2)]
    out = Tools(FakeClient(queued_rows=[rows, []]), max_rows=1000).host_log_patterns(limit=2)
    assert out["total_patterns"] == 5 and out["truncated"] is True
    rows = [_pattern_row(i, total_patterns=2) for i in range(2)]
    out = Tools(FakeClient(queued_rows=[rows, []]), max_rows=1000).host_log_patterns()
    assert out["truncated"] is False


def test_host_log_patterns_offset_and_host_pass_through():
    fake = FakeClient(queued_rows=[[_pattern_row(i) for i in range(2)], []])
    out = Tools(fake, max_rows=1000).host_log_patterns(limit=2, offset=2, host="h1")
    assert "LIMIT 2 OFFSET 2" in fake.all_sql[0] and len(fake.all_sql) == 2
    assert out["total_patterns"] == 5 and out["truncated"] is True  # 2 + 2 < 5
    fake = FakeClient(queued_rows=[[_pattern_row(i) for i in range(2)], []])
    out = Tools(fake, max_rows=1000).host_log_patterns(limit=2, offset=3)
    assert out["truncated"] is False  # 3 + 2 == 5: last page


def test_host_log_patterns_page_past_end_counts_separately():
    fake = FakeClient(queued_rows=[[], [{"total_patterns": 7}], [dict(_SENDER)]])
    out = Tools(fake, max_rows=1000).host_log_patterns(
        since="2026-10-01T00:00:00Z", until="2026-10-02T00:00:00Z", offset=500
    )
    assert len(fake.all_sql) == 3 and fake.all_sql[1].startswith("SELECT count() AS total_patterns")
    assert out["patterns"] == [] and out["total_patterns"] == 7 and out["truncated"] is False
    assert len(out["sources"]) == 1


def test_host_log_patterns_validation_errors_offset_and_host():
    tools = Tools(FakeClient(), max_rows=1000)
    assert tools.host_log_patterns(offset=-1)["error"] == "validation"
    assert tools.host_log_patterns(host="")["error"] == "validation"


def test_host_log_patterns_empty_still_returns_sources():
    out = Tools(FakeClient(queued_rows=[[], [dict(_SENDER)]]), max_rows=1000).host_log_patterns()
    assert out["patterns"] == [] and out["total_patterns"] == 0 and out["truncated"] is False
    assert len(out["sources"]) == 1


def test_host_log_patterns_validation_errors():
    tools = Tools(FakeClient(), max_rows=1000)
    assert tools.host_log_patterns(min_severity=9)["error"] == "validation"
    assert tools.host_log_patterns(min_severity=True)["error"] == "validation"
    assert tools.host_log_patterns(since="not-a-time")["error"] == "validation"


def test_host_log_patterns_upstream_error_passes_through():
    out = Tools(FakeClient(raise_exc=RuntimeError("ch down")), max_rows=1000).host_log_patterns()
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
