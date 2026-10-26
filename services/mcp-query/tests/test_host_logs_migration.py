"""infra/clickhouse/028_host_logs.sql: host_logs columns and TTL, the
Null-table -> materialized-view liveness wiring, and the ssdf_ro grants."""

from __future__ import annotations

import pathlib

MIGRATION = (
    pathlib.Path(__file__).resolve().parents[3] / "infra" / "clickhouse" / "028_host_logs.sql"
)


def _text() -> str:
    return MIGRATION.read_text(encoding="utf-8")


def test_migration_file_exists():
    assert MIGRATION.is_file()


def test_host_logs_columns_and_ttl():
    text = _text()
    for column in (
        "timestamp DateTime64(3, 'UTC')",
        "host      LowCardinality(String)",
        "source    LowCardinality(String)",
        "unit      LowCardinality(String)",
        "severity  UInt8",
        "message   String",
        "raw       String",
    ):
        assert column in text, column
    assert "TTL toDateTime(timestamp) + INTERVAL 30 DAY" in text
    assert "ORDER BY (timestamp, host)" in text


def test_liveness_is_null_table_feeding_a_summing_view():
    text = _text()
    assert "ENGINE = Null" in text
    assert "ENGINE = SummingMergeTree" in text
    assert (
        "CREATE MATERIALIZED VIEW IF NOT EXISTS ssdf.host_log_senders_mv TO ssdf.host_log_senders"
        in text
    )
    assert "FROM ssdf.host_log_lines" in text


def test_ssdf_ro_reads_logs_and_senders_only():
    text = _text()
    assert "GRANT SELECT ON ssdf.host_logs TO ssdf_ro" in text
    assert "GRANT SELECT ON ssdf.host_log_senders TO ssdf_ro" in text
    assert "host_log_lines TO" not in text


def test_no_placeholders_or_users():
    text = _text()
    assert "${" not in text
    assert "CREATE USER" not in text
