# src/ssdf_mcp_query/tools.py
"""Tool implementations: builders + guard + client -> result dicts."""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any

from .builders import (
    build_host_log_patterns,
    build_host_log_patterns_count,
    build_host_log_sources,
    build_query_flows,
    build_top_talkers,
    build_zone_matrix,
    BuilderError,
    HOST_LOG_PATTERNS_MAX_LIMIT,
    MAX_LIMIT,
    ZONE_MATRIX_MAX_LIMIT,
)
from .sql_guard import guard_sql, GuardError
from .timeparse import TimeParseError
from .untrusted_text import UntrustedText

logger = logging.getLogger("ssdf_mcp_query.tools")

# FLOW_COLUMNS fields that carry log-echoed free text with no enforced
# vocabulary at ingest. Everything else in FLOW_COLUMNS is numeric/IP/port/
# timestamp or a normalizer-derived field, so it is returned as-is.
_FLOW_UNTRUSTED_COLUMNS = (
    "rule_name",
    "user_name",
    "observer_ingress_zone",
    "observer_egress_zone",
)


# zone_matrix rows: zone names and observer hostnames are log-derived free text.
_ZONE_MATRIX_UNTRUSTED_COLUMNS = ("from_zone", "to_zone", "observer")


# host_log_patterns: every syslog sender is attacker-influenced; source/kind are fixed enums.
_HOST_LOG_SAMPLE_MAX_LEN = 500


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

    def zone_matrix(
        self, by="bytes", since=None, until=None, observer=None, limit=ZONE_MATRIX_MAX_LIMIT
    ) -> dict:
        """Zone-to-zone traffic per observer; flags truncation via a limit+1 probe row."""
        try:
            sql, params = build_zone_matrix(
                by=by, since=since, until=until, observer=observer, limit=limit
            )
        except (BuilderError, TimeParseError, ValueError) as exc:
            return {"error": "validation", "detail": str(exc)}
        clamped = max(1, min(int(limit), ZONE_MATRIX_MAX_LIMIT))
        result = self._safe_execute(sql, params, clamped + 1)
        if "rows" not in result:
            return result
        rows = result["rows"]
        truncated = len(rows) > clamped
        rows = _wrap_untrusted_columns(rows[:clamped], _ZONE_MATRIX_UNTRUSTED_COLUMNS)
        return {**result, "rows": rows, "row_count": len(rows), "truncated": truncated}

    def host_log_patterns(
        self, since=None, until=None, min_severity=3, limit=300, offset=0, host=None
    ) -> dict:
        """One page of normalized host-log error patterns plus per-sender liveness."""
        try:
            sql, params = build_host_log_patterns(
                since=since,
                until=until,
                min_severity=min_severity,
                limit=limit,
                offset=offset,
                host=host,
            )
        except (BuilderError, TimeParseError, ValueError) as exc:
            return {"error": "validation", "detail": str(exc)}
        clamped = max(1, min(int(limit), HOST_LOG_PATTERNS_MAX_LIMIT))
        found = self._safe_execute(sql, params, clamped)
        if "rows" not in found:
            return found
        if found["rows"]:
            total = found["rows"][0]["total_patterns"]
        elif offset:
            # A page past the end has no row to carry count() OVER (); count separately,
            # over the same resolved window.
            count_sql, count_params = build_host_log_patterns_count(
                since=params["since"], until=params["until"], min_severity=min_severity, host=host
            )
            counted = self._safe_execute(count_sql, count_params, 1)
            if "rows" not in counted:
                return counted
            total = counted["rows"][0]["total_patterns"] if counted["rows"] else 0
        else:
            total = 0
        sources_sql, sources_params = build_host_log_sources()
        senders = self._safe_execute(sources_sql, sources_params, 1000)
        if "rows" not in senders:
            return senders
        patterns = [
            {
                "host": UntrustedText.from_raw(row["host"]).to_response(),
                "source": row["source"],
                "unit": UntrustedText.from_raw(row["unit"]).to_response(),
                "kind": row["kind"],
                "severity": row["worst_severity"],
                "pattern": UntrustedText.from_raw(row["pattern"]).to_response(),
                "count": row["occurrences"],
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
                "sample": UntrustedText.from_raw(
                    row["sample"], max_len=_HOST_LOG_SAMPLE_MAX_LEN
                ).to_response(),
            }
            for row in found["rows"]
        ]
        sources = [
            {**row, "host": UntrustedText.from_raw(row["host"]).to_response()}
            for row in senders["rows"]
        ]
        return {
            "patterns": patterns,
            "total_patterns": total,
            "truncated": total > offset + len(patterns),
            "sources": sources,
        }

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

        Trust tier: operator-authored SQL, rows returned raw and to be treated as untrusted.
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
