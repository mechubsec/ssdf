"""infra/clickhouse/027_events_ocsf_authentication.sql must grant ssdf_events_export
the view only, never the underlying tables, so it cannot read events
columns (raw, ext) the view deliberately leaves out."""

from __future__ import annotations

import pathlib

MIGRATION = (
    pathlib.Path(__file__).resolve().parents[3]
    / "infra"
    / "clickhouse"
    / "027_events_ocsf_authentication.sql"
)


def _text() -> str:
    return MIGRATION.read_text(encoding="utf-8")


def test_migration_file_exists():
    assert MIGRATION.is_file()


def test_view_runs_with_sql_security_definer():
    text = _text()
    assert "DEFINER = ssdf_events_ocsf_definer SQL SECURITY DEFINER" in text
    assert "CREATE VIEW IF NOT EXISTS ssdf.events_ocsf_authentication_export" in text


def test_definer_identity_holds_the_base_table_grants():
    text = _text()
    assert "GRANT SELECT ON ssdf.events TO ssdf_events_ocsf_definer" in text


def test_export_identity_is_granted_the_view_only():
    """The querying identity must never hold a direct base-table grant --
    that would let it read columns the view leaves out on purpose, bypassing
    the DEFINER's narrower read surface entirely."""
    text = _text()
    assert "GRANT SELECT ON ssdf.events_ocsf_authentication_export TO ssdf_events_export" in text
    assert "GRANT SELECT ON ssdf.events TO ssdf_events_export" not in text
