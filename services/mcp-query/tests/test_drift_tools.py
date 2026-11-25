"""policy_drift tool: SQL building, truncation, unconfigured reader, run_sql refusal."""

import datetime as dt
import threading

import pytest

from ssdf_mcp_query.drift_tools import DriftTools, build_drift_sql
from ssdf_mcp_query.sql_guard import GuardError, guard_sql


def _build(**overrides):
    args = dict(
        verdict=None,
        flow_or_isolation_id=None,
        device=None,
        intent_commit=None,
        since_hours=168,
        limit=100,
    )
    args.update(overrides)
    return build_drift_sql(**args)


def test_hostile_text_is_bound_not_interpolated():
    sql, params = _build(device="'; DROP", flow_or_isolation_id="x' OR '1'='1")
    assert "DROP" not in sql and "OR '1'" not in sql
    assert params["device"] == "'; DROP"
    assert "{device:String}" in sql


def test_bad_verdict_raises():
    with pytest.raises(ValueError):
        _build(verdict="fine")


def test_limit_is_clamped():
    assert _build(limit=10_000)[1]["limit"] == 500


def test_since_hours_is_clamped():
    assert _build(since_hours=10**9)[1]["since_hours"] == 410 * 24
    assert _build(since_hours=-5)[1]["since_hours"] == 1


@pytest.mark.parametrize("field", ["limit", "since_hours"])
def test_non_numeric_argument_is_a_validation_error(field):
    out = DriftTools(lambda: _FakeClient(1), {}).policy_drift(**{field: "abc"})
    assert out["error"] == "validation"


class _FakeClient:
    def __init__(self, count):
        ts = dt.datetime(2026, 11, 24, 1, 2, 3, 456000, tzinfo=dt.timezone.utc)
        self.rows = [
            (ts, "s", "c", f"f{i}", "violating", "d", ["r1"], "e", 1, "p", f"h{i}")
            for i in range(count)
        ]
        self.calls = []

    def query(self, sql, parameters=None, settings=None):
        self.calls.append(parameters)
        self.settings = settings
        names = [
            "ts", "server_id", "intent_commit", "flow_or_isolation_id", "verdict", "device",
            "device_rule_ids", "evidence_ref", "labmode", "prev_hash", "row_hash",
        ]  # fmt: skip
        limit = parameters["limit"]
        return type("R", (), {"column_names": names, "result_rows": self.rows[:limit]})()


def test_truncated_when_cap_hit_and_rows_trimmed():
    tools = DriftTools(lambda: _FakeClient(10), {})
    out = tools.policy_drift(limit=3)
    assert out["truncated"] is True
    assert out["row_count"] == 3 and len(out["rows"]) == 3


def test_not_truncated_when_under_cap_and_shapes_row():
    out = DriftTools(lambda: _FakeClient(2), {}).policy_drift(limit=3)
    assert out["truncated"] is False and out["row_count"] == 2
    row = out["rows"][0]
    assert row["ts"] == "2026-11-24T01:02:03.456Z"
    assert row["labmode"] is True
    assert row["row_hash"] == "h0" and out["as_of"].endswith("Z")


def test_client_built_lazily_once_per_thread():
    built = []
    tools = DriftTools(lambda: built.append(1) or _FakeClient(0), {})
    assert built == []
    tools.policy_drift()
    tools.policy_drift()
    assert len(built) == 1
    worker = threading.Thread(target=tools.policy_drift)
    worker.start()
    worker.join()
    assert len(built) == 2


def test_unconfigured_reader_returns_error_without_client():
    assert DriftTools(None, {}).policy_drift() == {"error": "drift_reader_unconfigured"}


def test_bad_verdict_is_a_validation_error_not_a_raise():
    out = DriftTools(lambda: _FakeClient(0), {}).policy_drift(verdict="nope")
    assert out["error"] == "validation"


def test_run_sql_refuses_policy_drift():
    with pytest.raises(GuardError):
        guard_sql("SELECT * FROM ssdf.policy_drift")


def test_bounded_io_settings_reach_the_query():
    client = _FakeClient(0)
    settings = {"max_execution_time": 7, "max_result_rows": 9, "result_overflow_mode": "throw"}
    DriftTools(lambda: client, settings).policy_drift()
    assert client.settings == settings
