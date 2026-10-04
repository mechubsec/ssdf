"""infra/clickhouse/024_audit_ocsf_export.sql must grant ssdf_audit_export
the view only, never the underlying tables, so it cannot read audit_evidence
columns (args, error, data_classes, model_id, client_name) the view
deliberately leaves out."""

from __future__ import annotations

import pathlib

MIGRATION = (
    pathlib.Path(__file__).resolve().parents[3]
    / "infra"
    / "clickhouse"
    / "024_audit_ocsf_export.sql"
)


def _text() -> str:
    return MIGRATION.read_text(encoding="utf-8")


def test_migration_file_exists():
    assert MIGRATION.is_file()


def test_view_runs_with_sql_security_definer():
    text = _text()
    assert "DEFINER = ssdf_audit_ocsf_definer SQL SECURITY DEFINER" in text
    assert "CREATE VIEW IF NOT EXISTS ssdf.audit_ocsf_export" in text


def test_definer_identity_holds_the_base_table_grants():
    text = _text()
    assert "GRANT SELECT ON ssdf.audit_evidence TO ssdf_audit_ocsf_definer" in text
    assert "GRANT SELECT ON ssdf.audit_checkpoints TO ssdf_audit_ocsf_definer" in text


def test_export_identity_is_granted_the_view_only():
    """The querying identity must never hold a direct base-table grant --
    that would let it read columns the view leaves out on purpose, bypassing
    the DEFINER's narrower read surface entirely."""
    text = _text()
    assert "GRANT SELECT ON ssdf.audit_ocsf_export TO ssdf_audit_export" in text
    assert "GRANT SELECT ON ssdf.audit_evidence TO ssdf_audit_export" not in text
    assert "GRANT SELECT ON ssdf.audit_checkpoints TO ssdf_audit_export" not in text
