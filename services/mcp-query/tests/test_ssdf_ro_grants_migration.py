"""M16d: infra/clickhouse/018_ssdf_ro_grants.sql is the canonical, versioned
definition of what the ssdf_ro identity may read -- these tests keep it in
sync with sql_guard's application-layer exclusions rather than the two
drifting apart silently."""

from __future__ import annotations

import pathlib

from ssdf_mcp_query.sql_guard import _BLOCKED_TABLES

MIGRATION = (
    pathlib.Path(__file__).resolve().parents[3] / "infra" / "clickhouse" / "018_ssdf_ro_grants.sql"
)


def _text() -> str:
    return MIGRATION.read_text(encoding="utf-8")


def test_migration_file_exists():
    assert MIGRATION.is_file()


def test_creates_ssdf_ro():
    assert "CREATE USER IF NOT EXISTS ssdf_ro" in _text()


def test_grants_the_base_query_surface():
    text = _text()
    for table in (
        "ssdf.events",
        "ssdf.graph_nodes",
        "ssdf.graph_edges",
        "ssdf.entities",
        "ssdf.entity_edges",
        "ssdf.health_metrics",
        "ssdf_public.metric_timeseries",
        "ssdf_public.entity_series",
    ):
        assert f"GRANT SELECT ON {table} TO ssdf_ro" in text, table


def test_never_grants_audit_to_ssdf_ro():
    assert "GRANT SELECT ON ssdf.audit TO ssdf_ro" not in _text()


#  MEC-565's three audit-adjacent tables are never granted to ssdf_ro at all
#  (see 022/023/024_audit_*.sql) -- stricter than ssdf.audit's own "defense in
#  depth over a grant that exists for other tools" posture, since nothing
#  about them needs a general-purpose reader in the first place.
_NEVER_GRANTED_TO_SSDF_RO = {"audit", "audit_checkpoints", "audit_evidence", "audit_ocsf_export"}


def test_blocked_tables_match_sql_guard_exclusions():
    """Every table sql_guard refuses via run_sql either has an ssdf_ro grant
    documented here (defense in depth over a legitimate, narrowly-scoped
    reader) or is never granted at all (ssdf.audit and friends)."""
    text = _text()
    for table in _BLOCKED_TABLES:
        qualified = f"ssdf.{table}"
        if table in _NEVER_GRANTED_TO_SSDF_RO:
            assert f"GRANT SELECT ON {qualified} TO ssdf_ro" not in text
        else:
            assert f"GRANT SELECT ON {qualified} TO ssdf_ro" in text
