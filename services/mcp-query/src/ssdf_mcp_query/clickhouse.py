# src/ssdf_mcp_query/clickhouse.py
"""Read-only ClickHouse access (the swappable storage seam)."""

from __future__ import annotations

import datetime as _dt
import ipaddress as _ip
import threading
from typing import Any

import clickhouse_connect

from .config import Config, ch_tls_kwargs


def jsonify(value: Any) -> Any:
    """Convert ClickHouse-returned values into JSON-serializable Python primitives."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, _dt.datetime):
        return value.isoformat()
    if isinstance(value, (_ip.IPv4Address, _ip.IPv6Address)):
        return str(value)
    if isinstance(value, dict):
        return {k: jsonify(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [jsonify(v) for v in value]
    return str(value)


def query_settings(config: Config) -> dict:
    """The bounded-I/O settings every read query carries (services/AGENTS.md)."""
    return {
        "max_execution_time": config.max_execution_time,
        "max_result_rows": config.max_result_rows,
        "max_memory_usage": config.max_memory_usage,
        "result_overflow_mode": "throw",
    }


class ClickHouseClient:
    """Thin read-only client. All queries run as the configured (read-only) CH user.

    A ``clickhouse_connect`` client owns a single HTTP session and the driver
    rejects concurrent queries on it ("Attempt to execute concurrent queries
    within the same session"). FastMCP dispatches sync tool calls on a worker
    thread pool, so sibling tool invocations run on different threads. We
    therefore keep one underlying driver client per thread (``threading.local``)
    rather than sharing a single instance across threads.
    """

    def __init__(self, config: Config):
        self._config = config
        self._local = threading.local()
        # Connect eagerly on the constructing thread so misconfiguration or an
        # unreachable ClickHouse fails fast at startup; worker threads create
        # their own client lazily on first use.
        self._connect()

    def _connect(self):
        client = clickhouse_connect.get_client(
            host=self._config.ch_host,
            port=self._config.ch_port,
            username=self._config.ch_user,
            password=self._config.ch_password.get(),
            database=self._config.ch_database,
            **ch_tls_kwargs(self._config),
        )
        self._local.client = client
        return client

    def _client_for_thread(self):
        client = getattr(self._local, "client", None)
        if client is None:
            client = self._connect()
        return client

    def run(self, sql: str, params: dict | None = None) -> dict:
        """Execute a read query; return {columns, rows, row_count}. Rows are dicts."""
        result = self._client_for_thread().query(
            sql,
            parameters=params or {},
            settings=query_settings(self._config),
        )
        columns = list(result.column_names)
        rows = [{col: jsonify(val) for col, val in zip(columns, row)} for row in result.result_rows]
        return {"columns": columns, "rows": rows, "row_count": len(rows)}
