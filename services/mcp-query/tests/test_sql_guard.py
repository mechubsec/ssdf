import pytest
from ssdf_mcp_query.sql_guard import guard_sql, GuardError

ALLOWED = [
    "SELECT * FROM ssdf.events LIMIT 10",
    "SELECT event_action, count() FROM ssdf.events GROUP BY event_action",
    "SELECT * FROM ssdf.events WHERE event_outcome = 'failure' ORDER BY timestamp DESC",
    "SELECT s.source_ip FROM ssdf.events AS s WHERE s.destination_port = 443",
]

DENIED = [
    "INSERT INTO ssdf.events VALUES (1)",
    "ALTER TABLE ssdf.events DELETE WHERE 1=1",
    "DROP TABLE ssdf.events",
    "SELECT * FROM ssdf.events; DELETE FROM ssdf.events",
    "SELECT * FROM system.tables",
    "SELECT * FROM url('http://evil/x', CSV, 'a String')",
    "SELECT * FROM ssdf.events SETTINGS readonly=0",
    "SELECT * FROM events",
    "SELECT * FROM other.secrets",
    "TRUNCATE TABLE ssdf.events",
    "SELECT * FROM SSDF.events",
    "SELECT * FROM system.tables UNION ALL SELECT event_action FROM ssdf.events",
    "WITH x AS (SELECT * FROM system.tables) SELECT * FROM x",
]


@pytest.mark.parametrize("query", ALLOWED)
def test_allowed_queries_pass(query):
    out = guard_sql(query, max_limit=1000)
    assert "ssdf" in out.lower()
    assert "limit" in out.lower()


@pytest.mark.parametrize("query", DENIED)
def test_denied_queries_rejected(query):
    with pytest.raises(GuardError):
        guard_sql(query, max_limit=1000)


# L2: the structural check (FROM target must be a plain ssdf identifier) is the
# boundary — these MUST be rejected even when absent from the internal denylist
# (gcs, azureBlobStorage, iceberg, deltaLake, mongodb, redis, sqlite, executable).
TABLE_FUNCTIONS = [
    "s3",
    "url",
    "file",
    "remote",
    "remoteSecure",
    "gcs",
    "azureBlobStorage",
    "iceberg",
    "deltaLake",
    "mongodb",
    "redis",
    "sqlite",
    "executable",
    "cluster",
    "jdbc",
    "odbc",
]


@pytest.mark.parametrize("fn", TABLE_FUNCTIONS)
def test_table_functions_rejected_structurally(fn):
    with pytest.raises(GuardError):
        guard_sql(f"SELECT * FROM {fn}('arg1', 'arg2')", max_limit=1000)


def test_missing_limit_is_injected():
    out = guard_sql("SELECT * FROM ssdf.events", max_limit=500)
    assert out.lower().rstrip().endswith("limit 500")


def test_oversized_limit_is_clamped():
    out = guard_sql("SELECT * FROM ssdf.events LIMIT 999999", max_limit=1000)
    assert "1000" in out
    assert "999999" not in out


def test_lowercase_ssdf_table_is_allowed():
    out = guard_sql("SELECT * FROM ssdf.events", max_limit=1000)
    assert "ssdf.events" in out.lower()
    assert "limit" in out.lower()


# M16d: a run_sql-only token must not be able to read these tables directly,
# even though ssdf_ro holds SELECT on them for other, access-controlled tools
# (reidentify, fabric_status, the audit hash-chain seed).
BLOCKED_TABLES = [
    "audit",
    "pseudonym_map",
    "topo_observations",
    # MEC-565
    "audit_checkpoints",
    "audit_evidence",
    "audit_ocsf_export",
]


@pytest.mark.parametrize("table", BLOCKED_TABLES)
def test_blocked_tables_rejected(table):
    with pytest.raises(GuardError):
        guard_sql(f"SELECT * FROM ssdf.{table}", max_limit=1000)


@pytest.mark.parametrize("table", BLOCKED_TABLES)
def test_blocked_tables_rejected_case_insensitive(table):
    with pytest.raises(GuardError):
        guard_sql(f"SELECT * FROM ssdf.{table.upper()}", max_limit=1000)


def test_pseudonym_map_reversal_is_refused():
    """The concrete exploit this guards against: reversing a surrogate via run_sql
    instead of the access-controlled reidentify tool."""
    with pytest.raises(GuardError):
        guard_sql(
            "SELECT real_value FROM ssdf.pseudonym_map WHERE surrogate = 'h_3f9a'",
            max_limit=1000,
        )


def test_blocked_table_rejected_via_join():
    with pytest.raises(GuardError):
        guard_sql(
            "SELECT e.* FROM ssdf.events AS e "
            "JOIN ssdf.pseudonym_map AS p ON e.source_ip = p.real_value",
            max_limit=1000,
        )


# F1: ClickHouse reads `x IN t` / `x IN (t)` (default db `ssdf`) and the
# globalNotIn/notIn/nullIn function family as `x IN (SELECT * FROM t)`, but
# sqlglot parses the right-hand side as a bare Column, not a Table -- so the
# _BLOCKED_TABLES walk over exp.Table never saw it and a run_sql-only token
# could reverse a surrogate via `src_ip IN ssdf.pseudonym_map`.
IN_TABLE_BYPASSES = [
    "SELECT * FROM ssdf.events WHERE src_ip IN ssdf.pseudonym_map",
    "SELECT * FROM ssdf.events WHERE src_ip GLOBAL IN ssdf.pseudonym_map",
    "SELECT * FROM ssdf.events WHERE src_ip NOT IN ssdf.audit",
    "SELECT * FROM ssdf.events WHERE src_ip IN (ssdf.pseudonym_map)",
    "SELECT * FROM ssdf.events WHERE src_ip IN pseudonym_map",
    "SELECT * FROM ssdf.events WHERE globalNotIn(src_ip, ssdf.pseudonym_map)",
    "SELECT * FROM ssdf.events WHERE notIn(src_ip, ssdf.pseudonym_map)",
    "SELECT * FROM ssdf.events WHERE nullIn(src_ip, ssdf.topo_observations)",
    # Extra parens wrap the Column in exp.Paren; ClickHouse still reads a table.
    "SELECT * FROM ssdf.events WHERE src_ip IN ((ssdf.pseudonym_map))",
    "SELECT * FROM ssdf.events WHERE src_ip IN (((pseudonym_map)))",
    "SELECT * FROM ssdf.events WHERE src_ip NOT IN ((ssdf.audit))",
    "SELECT * FROM ssdf.events WHERE src_ip IN ((ssdf.pseudonym_map), '192.0.2.1')",
]


@pytest.mark.parametrize("query", IN_TABLE_BYPASSES)
def test_in_table_bypass_rejected(query):
    with pytest.raises(GuardError):
        guard_sql(query, max_limit=1000)


# Legitimate IN forms (literal lists, subqueries, tuple-lists) must keep working.
IN_STILL_ALLOWED = [
    "SELECT * FROM ssdf.events WHERE src_ip IN ('192.0.2.1','192.0.2.2')",
    "SELECT * FROM ssdf.events WHERE dst_port IN (22, 443)",
    "SELECT * FROM ssdf.events WHERE src_ip IN (SELECT source_ip FROM ssdf.events)",
    "SELECT * FROM ssdf.events WHERE (src_ip, dst_port) IN (('192.0.2.1', 22))",
]


@pytest.mark.parametrize("query", IN_STILL_ALLOWED)
def test_in_legitimate_forms_still_allowed(query):
    out = guard_sql(query, max_limit=1000)
    assert "ssdf" in out.lower()
