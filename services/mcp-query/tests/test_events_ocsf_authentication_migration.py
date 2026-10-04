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


def test_view_never_projects_ext_or_raw():
    """F1: ext/raw carry attacker-influenceable and device-internal text the
    view's own comments say it deliberately leaves out. Catching this by
    string search is a backstop; test_events_ocsf_views_contract.py proves
    it against a real ClickHouse."""
    text = _text()
    assert "e.ext" not in text
    assert "e.raw" not in text


def test_view_never_uses_arrayjoin():
    """F4: arrayJoin(event_category) produced one output row per category,
    duplicating any multi-category event under every category it carries."""
    sql_lines = (line for line in _text().splitlines() if not line.strip().startswith("--"))
    assert "arrayJoin" not in "\n".join(sql_lines)


def test_definer_password_is_not_shared_with_the_audit_ocsf_definer():
    """F5: 026/027's ssdf_events_ocsf_definer must use its own placeholder,
    not 024's ${OCSF_DEFINER_PW} -- they are different privilege domains and
    must not share a credential."""
    text = _text()
    assert "${EVENTS_OCSF_DEFINER_PW}" in text
    assert "${OCSF_DEFINER_PW}" not in text
