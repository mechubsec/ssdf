# src/ssdf_mcp_query/tools.py
"""Tool implementations: builders + guard + client -> result dicts."""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any

from .builders import build_query_flows, build_top_talkers, BuilderError, MAX_LIMIT
from .sql_guard import guard_sql, GuardError
from .timeparse import TimeParseError
from .untrusted_text import UntrustedText

logger = logging.getLogger("ssdf_mcp_query.tools")

# FLOW_COLUMNS fields that carry attacker-reachable free text: both are written
# from unauthenticated syslog ingest (see docs/security/2026-06-10-vulnerability-
# review.md H1) and, unlike event_action/event_outcome/event_provider/
# network_transport/zones (fixed, normalizer-controlled vocabularies), can hold
# arbitrary text. Everything else in FLOW_COLUMNS is numeric/IP/port/timestamp or
# one of those bounded-vocabulary fields, so it is returned as-is.
_FLOW_UNTRUSTED_COLUMNS = ("rule_name", "user_name")


def _ok(result: dict, requested_limit: int) -> dict:
    rows = result["rows"]
    return {
        "rows": rows,
        "columns": result["columns"],
        "row_count": result["row_count"],
        "truncated": result["row_count"] >= requested_limit,
        "elapsed_ms": result.pop("_elapsed_ms", 0),
    }


def _wrap_untrusted_columns(rows: list[dict], columns: tuple[str, ...]) -> list[dict]:
    """Replace known log-echoed free-text columns in-place with UntrustedText responses."""
    for row in rows:
        for col in columns:
            if col in row:
                row[col] = UntrustedText.from_raw(row[col]).to_response()
    return rows


class Tools:
    """Stateless tool surface bound to a ClickHouse client."""

    def __init__(self, client, max_rows: int = MAX_LIMIT):
        self._client = client
        self._max_rows = max_rows

    def _execute(self, sql: str, params: dict, requested_limit: int) -> dict:
        start = time.monotonic()
        result = self._client.run(sql, params)
        result["_elapsed_ms"] = int((time.monotonic() - start) * 1000)
        return _ok(result, requested_limit)

    def query_flows(
        self,
        src_ip=None,
        dst_ip=None,
        dst_port=None,
        action=None,
        outcome=None,
        provider=None,
        zone=None,
        since=None,
        until=None,
        limit=100,
    ) -> dict:
        try:
            sql, params = build_query_flows(
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                action=action,
                outcome=outcome,
                provider=provider,
                zone=zone,
                since=since,
                until=until,
                limit=limit,
            )
        except (BuilderError, TimeParseError, ValueError) as exc:
            return {"error": "validation", "detail": str(exc)}
        result = self._safe_execute(sql, params, min(int(limit), self._max_rows))
        if "rows" in result:
            _wrap_untrusted_columns(result["rows"], _FLOW_UNTRUSTED_COLUMNS)
        return result

    def top_talkers(self, by="bytes", side="src", since=None, until=None, limit=10) -> dict:
        try:
            sql, params = build_top_talkers(by=by, side=side, since=since, until=until, limit=limit)
        except (BuilderError, TimeParseError, ValueError) as exc:
            return {"error": "validation", "detail": str(exc)}
        return self._safe_execute(sql, params, int(limit))

    def describe_schema(self) -> dict:
        try:
            cols = self._client.run("DESCRIBE ssdf.events")
            columns = [{"name": r["name"], "type": r["type"]} for r in cols["rows"]]
            enums: dict[str, Any] = {}
            for key, col in (
                ("event_actions", "event_action"),
                ("event_outcomes", "event_outcome"),
                ("event_providers", "event_provider"),
            ):
                res = self._client.run(f"SELECT DISTINCT {col} AS v FROM ssdf.events LIMIT 100")
                enums[key] = [r["v"] for r in res["rows"]]
            zones = self._client.run(
                "SELECT DISTINCT observer_ingress_zone AS v FROM ssdf.events "
                "WHERE v != '' LIMIT 100"
            )
            stats = self._client.run(
                "SELECT count() AS c, min(timestamp) AS mn, max(timestamp) AS mx FROM ssdf.events"
            )
            stat_row = stats["rows"][0] if stats["rows"] else {"c": 0, "mn": None, "mx": None}
            return {
                "columns": columns,
                "zones": [r["v"] for r in zones["rows"]],
                "row_count": stat_row["c"],
                "time_range": {"min": stat_row["mn"], "max": stat_row["mx"]},
                **enums,
            }
        except Exception:  # noqa: BLE001 - surface as scrubbed upstream error
            cid = uuid.uuid4().hex
            logger.exception("describe_schema upstream error correlation_id=%s", cid)
            return {"error": "upstream", "detail": "query failed", "correlation_id": cid}

    def run_sql(self, query: str) -> dict:
        """Run an operator-authored, read-only SQL query (guarded by sql_guard).

        Contract: unlike the purpose-built tools above, the row shape here is
        whatever columns the caller's own SELECT names, so there is no fixed
        allowlist of free-text columns to wrap. Rows are returned RAW -- every
        string-typed cell must be treated by the caller as untrusted,
        log-derived free text (same threat model as UntrustedText) unless the
        caller's own query is known to select only structural/numeric columns.
        This tool is for operators composing their own SQL, a different trust
        tier from the fixed-shape tools, so unsanitized-raw is the documented
        contract rather than an oversight.
        """
        try:
            safe_sql = guard_sql(query, max_limit=self._max_rows)
        except GuardError as exc:
            return {"error": "validation", "detail": str(exc)}
        return self._safe_execute(safe_sql, {}, self._max_rows)

    def _safe_execute(self, sql: str, params: dict, requested_limit: int) -> dict:
        try:
            return self._execute(sql, params, requested_limit)
        except Exception:  # noqa: BLE001 - upstream/CH failures, scrubbed
            cid = uuid.uuid4().hex
            logger.exception("tool upstream error correlation_id=%s", cid)
            return {"error": "upstream", "detail": "query failed", "correlation_id": cid}
