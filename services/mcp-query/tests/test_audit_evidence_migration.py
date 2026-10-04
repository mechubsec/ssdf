"""MEC-565: infra/clickhouse/023_audit_evidence.sql must retain rows well
past ssdf.audit's 90-day TTL -- the acceptance floor is 400 days, so this
pins the table to something above that rather than letting it silently
regress back toward 90."""

from __future__ import annotations

import pathlib
import re

MIGRATION = (
    pathlib.Path(__file__).resolve().parents[3] / "infra" / "clickhouse" / "023_audit_evidence.sql"
)


def _text() -> str:
    return MIGRATION.read_text(encoding="utf-8")


def test_migration_file_exists():
    assert MIGRATION.is_file()


def test_creates_audit_evidence_table():
    assert "CREATE TABLE IF NOT EXISTS ssdf.audit_evidence" in _text()


def test_ttl_is_at_least_400_days():
    match = re.search(r"TTL\s+toDateTime\(ts\)\s*\+\s*INTERVAL\s+(\d+)\s+DAY", _text())
    assert match, "expected a TTL ... INTERVAL <n> DAY clause"
    assert int(match.group(1)) >= 400


def test_carries_the_hash_chain_columns_so_archived_rows_still_verify():
    text = _text()
    for column in ("prev_hash", "row_hash"):
        assert column in text


def test_grants_archiver_select_and_insert_only():
    text = _text()
    assert "GRANT SELECT ON ssdf.audit TO ssdf_archiver" in text
    assert "GRANT INSERT, SELECT ON ssdf.audit_evidence TO ssdf_archiver" in text
    assert "ALTER" not in text
    assert "DELETE" not in text


def test_does_not_grant_ssdf_ro():
    """Bulk export access stays scoped narrowly to ssdf_audit_export in
    024_audit_ocsf_export.sql; ssdf_ro is never opened to audit content."""
    assert "TO ssdf_ro" not in _text()


def test_grants_select_to_verify_and_checkpoint_identities():
    """ssdf_audit_verify and ssdf_checkpoint need to read audit_evidence to
    bridge a dangling predecessor across ssdf.audit's TTL boundary to a
    checkpoint anchor."""
    text = _text()
    assert "GRANT SELECT ON ssdf.audit_evidence TO ssdf_audit_verify" in text
    assert "GRANT SELECT ON ssdf.audit_evidence TO ssdf_checkpoint" in text
