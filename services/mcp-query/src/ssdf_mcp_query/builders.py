# src/ssdf_mcp_query/builders.py
"""Pure SQL builders for the purpose-built tools. Return (sql, params); no I/O."""

from __future__ import annotations

from .timeparse import parse_time

MAX_LIMIT = 1000
TOP_MAX_LIMIT = 100
ZONE_MATRIX_MAX_LIMIT = 500

FLOW_COLUMNS = [
    "timestamp",
    "event_action",
    "event_outcome",
    "event_provider",
    "source_ip",
    "source_port",
    "destination_ip",
    "destination_port",
    "network_transport",
    "network_bytes",
    "rule_name",
    "observer_ingress_zone",
    "observer_egress_zone",
    "user_name",
]


class BuilderError(ValueError):
    """Raised on invalid builder arguments."""


def _clamp(value: int, lo: int, hi: int) -> int:
    return max(lo, min(int(value), hi))


def _window(since, until, params):
    """Bind the time window (defaults: now-24h .. now) into params and return conditions."""
    since_dt = parse_time(since) if since else parse_time("now-24h")
    until_dt = parse_time(until) if until else parse_time("now")
    params["since"] = since_dt.isoformat()
    params["until"] = until_dt.isoformat()
    return [
        "timestamp >= parseDateTimeBestEffort({since:String})",
        "timestamp <= parseDateTimeBestEffort({until:String})",
    ]


def build_query_flows(
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
):
    params: dict = {}
    conditions = _window(since, until, params)

    if src_ip is not None:
        params["src_ip"] = src_ip
        conditions.append("source_ip = toIPv4({src_ip:String})")
    if dst_ip is not None:
        params["dst_ip"] = dst_ip
        conditions.append("destination_ip = toIPv4({dst_ip:String})")
    if dst_port is not None:
        params["dst_port"] = int(dst_port)
        conditions.append("destination_port = {dst_port:UInt16}")
    if action is not None:
        params["action"] = action
        conditions.append("event_action = {action:String}")
    if outcome is not None:
        params["outcome"] = outcome
        conditions.append("event_outcome = {outcome:String}")
    if provider is not None:
        params["provider"] = provider
        conditions.append("event_provider = {provider:String}")
    if zone is not None:
        params["zone"] = zone
        conditions.append(
            "(observer_ingress_zone = {zone:String} OR observer_egress_zone = {zone:String})"
        )

    where = " AND ".join(conditions)
    cols = ", ".join(FLOW_COLUMNS)
    limit = _clamp(limit, 1, MAX_LIMIT)
    sql = f"SELECT {cols} FROM ssdf.events WHERE {where} ORDER BY timestamp DESC LIMIT {limit}"
    return sql, params


def build_top_talkers(by="bytes", side="src", since=None, until=None, limit=10):
    if by not in ("bytes", "flows"):
        raise BuilderError("by must be 'bytes' or 'flows'")
    if side not in ("src", "dst"):
        raise BuilderError("side must be 'src' or 'dst'")

    ip_col = "source_ip" if side == "src" else "destination_ip"
    order_expr = "sum(network_bytes)" if by == "bytes" else "count()"
    params: dict = {}
    conditions = _window(since, until, params)
    conditions.append(f"{ip_col} IS NOT NULL")
    where = " AND ".join(conditions)
    limit = _clamp(limit, 1, TOP_MAX_LIMIT)
    sql = (
        f"SELECT {ip_col} AS ip, sum(network_bytes) AS bytes, count() AS flows "
        f"FROM ssdf.events WHERE {where} "
        f"GROUP BY ip ORDER BY {order_expr} DESC LIMIT {limit}"
    )
    return sql, params


def build_zone_matrix(
    by="bytes", since=None, until=None, observer=None, limit=ZONE_MATRIX_MAX_LIMIT
):
    """Traffic per (ingress zone, egress zone, observer) over a window.

    Fetches ``limit + 1`` rows so the caller can report truncation. Rows with an
    empty zone are excluded: the zone columns are non-Nullable ``LowCardinality(String)``
    and ingest writes ``''`` when a log line carries no zone.
    """
    if by not in ("bytes", "flows"):
        raise BuilderError("by must be 'bytes' or 'flows'")
    params: dict = {}
    conditions = _window(since, until, params)
    conditions.append("observer_ingress_zone != ''")
    conditions.append("observer_egress_zone != ''")
    if observer is not None:
        conditions.append("observer_hostname = {observer:String}")
        params["observer"] = observer
    where = " AND ".join(conditions)
    limit = _clamp(limit, 1, ZONE_MATRIX_MAX_LIMIT)
    # Secondary keys make the order (and so which rows survive truncation) deterministic.
    sql = (
        "SELECT observer_ingress_zone AS from_zone, observer_egress_zone AS to_zone, "
        "observer_hostname AS observer, sum(network_bytes) AS bytes, count() AS flows "
        f"FROM ssdf.events WHERE {where} "
        f"GROUP BY from_zone, to_zone, observer "
        f"ORDER BY {by} DESC, from_zone, to_zone, observer LIMIT {limit + 1}"
    )
    return sql, params
