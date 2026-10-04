"""Validate and rewrite LLM-supplied SQL for the guarded run_sql tool.

Layered defenses: single statement, SELECT-only, no SETTINGS clause, ssdf-only
tables, no table functions, enforced/clamped LIMIT. Returns safe SQL or raises.
"""

from __future__ import annotations

import sqlglot
from sqlglot import exp

ALLOWED_DB = "ssdf"
_DIALECT = "clickhouse"

# Tables ssdf_ro can SELECT for other, narrowly-scoped tools (reidentify,
# fabric_status, audit chain seeding) but that run_sql must never reach
# directly: a generic ad hoc query is not the access-controlled path those
# tools provide, and DB grants alone are one drift away from a direct
# pseudonym reversal or audit-trail read (see infra/clickhouse/018_ssdf_ro_grants.sql).
_BLOCKED_TABLES = {
    "audit",
    "pseudonym_map",
    "topo_observations",
    # MEC-565: ssdf_ro holds no grant on any of these (022/023/024), so this
    # is defense in depth, not the primary control -- same posture as `audit`
    # above, for the same reason: who-did-what content stays off the generic
    # run_sql surface even if a future grant drifts.
    "audit_checkpoints",
    "audit_evidence",
    "audit_ocsf_export",
}
# ClickHouse's IN-family functions accept a bare table name as the set
# (`globalNotIn(x, ssdf.t)`); sqlglot leaves them as Anonymous calls.
_IN_FUNCTIONS = {
    "in",
    "notin",
    "globalin",
    "globalnotin",
    "nullin",
    "notnullin",
    "globalnullin",
    "globalnotnullin",
}
_TABLE_FUNCTIONS = {
    "url",
    "file",
    "remote",
    "remotesecure",
    "s3",
    "s3cluster",
    "mysql",
    "postgresql",
    "jdbc",
    "odbc",
    "hdfs",
    "cluster",
    "merge",
    "input",
    "numbers",
    "generaterandom",
    "view",
    "dictionary",
}


class GuardError(ValueError):
    """Raised when a query is rejected by the guard."""


def guard_sql(query: str, max_limit: int = 1000) -> str:
    """Return rewritten safe SQL for a single read-only SELECT, or raise GuardError."""
    try:
        statements = sqlglot.parse(query, read=_DIALECT)
    except Exception as exc:
        raise GuardError(f"could not parse query: {exc}") from exc

    statements = [s for s in statements if s is not None]
    if len(statements) != 1:
        raise GuardError("exactly one statement is allowed")

    stmt = statements[0]
    if not isinstance(stmt, exp.Select):
        raise GuardError("only SELECT statements are allowed")

    if stmt.args.get("settings"):
        raise GuardError("SETTINGS clause is not allowed")

    for func in stmt.find_all(exp.Anonymous, exp.Func):
        name = (func.name or "").lower()
        if name in _TABLE_FUNCTIONS:
            raise GuardError(f"table function not allowed: {name}")

    # ClickHouse reads `x IN ssdf.t` / `x IN (ssdf.t)` / `x IN t` as
    # `x IN (SELECT * FROM ssdf.t)`, but sqlglot parses the right-hand operand
    # as a Column, so the Table walk below never sees it. The right side of IN
    # must be a subquery or a list of non-column values.
    for node in stmt.find_all(exp.In):
        # find(), not isinstance(): `x IN ((ssdf.t))` wraps the Column in Paren.
        if node.args.get("field") is not None or any(
            e.find(exp.Column) is not None for e in node.expressions
        ):
            raise GuardError("IN must take a subquery or a literal list, not a table name")
    for func in stmt.find_all(exp.Anonymous):
        if (func.name or "").lower() in _IN_FUNCTIONS:
            raise GuardError(f"function not allowed: {func.name}")

    tables = list(stmt.find_all(exp.Table))
    if not tables:
        raise GuardError("query must read from an ssdf table")
    for table in tables:
        # A table function (e.g. url(...)) parses as Table wrapping an
        # Anonymous/Func with no db/name; reject anything not a plain ssdf table.
        if not isinstance(table.this, exp.Identifier):
            raise GuardError("table functions are not allowed")
        db = table.db or ""
        if db != ALLOWED_DB:
            raise GuardError(
                f"only the '{ALLOWED_DB}' database is allowed (got {table.db or 'unqualified'}.{table.name})"
            )
        name = (table.name or "").lower()
        if name in _BLOCKED_TABLES:
            raise GuardError(f"table '{ALLOWED_DB}.{table.name}' is not queryable via run_sql")

    limit = stmt.args.get("limit")
    if limit is None:
        stmt = stmt.limit(max_limit)
    else:
        expr = limit.expression
        if isinstance(expr, exp.Literal) and expr.is_int:
            if int(expr.name) > max_limit:
                stmt.set("limit", exp.Limit(expression=exp.Literal.number(max_limit)))
        else:
            stmt.set("limit", exp.Limit(expression=exp.Literal.number(max_limit)))

    return stmt.sql(dialect=_DIALECT)
