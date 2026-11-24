"""ssdf#104: infra/clickhouse/029_policy_drift.sql text checks."""

from __future__ import annotations

import pathlib
import re

import pytest

from ssdf_mcp_query.sql_guard import GuardError, guard_sql

MIGRATION = (
    pathlib.Path(__file__).resolve().parents[3] / "infra" / "clickhouse" / "029_policy_drift.sql"
)


def _text() -> str:
    return MIGRATION.read_text(encoding="utf-8")


def test_creates_policy_drift_table():
    assert "CREATE TABLE IF NOT EXISTS ssdf.policy_drift" in _text()


def test_ttl_is_at_least_410_days():
    match = re.search(r"TTL\s+toDateTime\(ts\)\s*\+\s*INTERVAL\s+(\d+)\s+DAY", _text())
    assert match, "expected a TTL ... INTERVAL <n> DAY clause"
    assert int(match.group(1)) >= 410


def test_carries_the_hash_chain_columns():
    text = _text()
    for column in ("prev_hash", "row_hash"):
        assert column in text


def test_has_insert_dedup_window_like_016():
    assert re.search(r"non_replicated_deduplication_window\s*=\s*10000", _text())


def test_writer_is_insert_only():
    text = _text()
    assert "GRANT INSERT ON ssdf.policy_drift TO ssdf_drift;" in text
    assert not re.search(r"GRANT[^;]*SELECT[^;]*TO ssdf_drift", text)
    assert "ALTER" not in text
    assert "DELETE" not in text


def test_verifier_can_read_and_ssdf_ro_cannot():
    text = _text()
    assert "GRANT SELECT ON ssdf.policy_drift TO ssdf_audit_verify;" in text
    assert "TO ssdf_ro" not in text


def test_user_password_is_a_placeholder():
    assert "'${DRIFT_PW}'" in _text()


def test_sql_guard_refuses_policy_drift():
    with pytest.raises(GuardError):
        guard_sql("SELECT * FROM ssdf.policy_drift", max_limit=1000)
