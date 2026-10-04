"""MEC-565: infra/clickhouse/022_audit_checkpoints.sql keeps a few load-bearing
properties -- No TTL (checkpoints must outlive the rows they anchor), and
checkpoint_ts stored as String (so the signed bytes round-trip exactly, see
checkpoint_verify.py)."""

from __future__ import annotations

import pathlib

MIGRATION = (
    pathlib.Path(__file__).resolve().parents[3]
    / "infra"
    / "clickhouse"
    / "022_audit_checkpoints.sql"
)


def _text() -> str:
    return MIGRATION.read_text(encoding="utf-8")


def _sql_only() -> str:
    """``_text()`` with ``--`` comment lines stripped, so a migration's own
    prose (which freely discusses TTL/ALTER/DELETE to explain why the DDL
    below avoids them) cannot make these checks pass or fail on the wrong
    thing."""
    return "\n".join(line for line in _text().splitlines() if not line.strip().startswith("--"))


def test_migration_file_exists():
    assert MIGRATION.is_file()


def test_creates_audit_checkpoints_table():
    assert "CREATE TABLE IF NOT EXISTS ssdf.audit_checkpoints" in _text()


def test_has_no_ttl():
    """A checkpoint must outlive the rows it anchors, or it cannot do its job."""
    assert "TTL" not in _sql_only()


def test_checkpoint_ts_is_a_string_not_a_datetime():
    """Must NOT be DateTime64: the signature covers the exact literal string
    the Rust signer produced, and round-tripping through a ClickHouse
    DateTime64 column is not guaranteed to reproduce the same bytes."""
    assert "checkpoint_ts  String" in _text() or "checkpoint_ts String" in _text()
    assert "checkpoint_ts  DateTime" not in _text()


def test_grants_checkpoint_writer_select_and_insert_only():
    text = _text()
    assert "GRANT SELECT ON ssdf.audit TO ssdf_checkpoint" in text
    assert "GRANT INSERT, SELECT ON ssdf.audit_checkpoints TO ssdf_checkpoint" in text
    sql_only = _sql_only()
    assert "ALTER" not in sql_only
    assert "DELETE" not in sql_only


def test_grants_verifier_read_access_to_checkpoints():
    assert "GRANT SELECT ON ssdf.audit_checkpoints TO ssdf_audit_verify" in _text()
