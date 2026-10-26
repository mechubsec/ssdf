# src/ssdf_mcp_query/builders.py
"""Pure SQL builders for the purpose-built tools. Return (sql, params); no I/O."""

from __future__ import annotations

from .timeparse import parse_time

MAX_LIMIT = 1000
TOP_MAX_LIMIT = 100
ZONE_MATRIX_MAX_LIMIT = 500
HOST_LOG_PATTERNS_MAX_LIMIT = 500
HOST_LOG_PATTERNS_MAX_OFFSET = 100_000

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
    and ingest writes ``''`` when a log line carries no zone. ``network_bytes`` is
    Nullable, so ``ifNull`` keeps an all-NULL group at 0 instead of NULL.
    """
    if by not in ("bytes", "flows"):
        raise BuilderError("by must be 'bytes' or 'flows'")
    params: dict = {}
    conditions = _window(since, until, params)
    # Flow events only: non-flow records (threat, screen, ...) carry zones too and
    # would inflate `flows` (same scoping as public-metrics volume measures).
    conditions.append("event_action LIKE 'flow_%'")
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
        "observer_hostname AS observer, sum(ifNull(network_bytes, 0)) AS bytes, count() AS flows "
        f"FROM ssdf.events WHERE {where} "
        "GROUP BY from_zone, to_zone, observer "
        f"ORDER BY {by} DESC, from_zone, to_zone, observer LIMIT {limit + 1}"
    )
    return sql, params


# host_log_patterns message normalization, applied in this order (callers key memory
# on the result, so the contract is fixed). Python raw strings; rendered into SQL by
# _ch_literal. The IPv6 step emits a digit-free token so step 5 cannot touch it; it is
# swapped for <ip6> afterwards. \1 keeps the guard character in front of the address.
_HOST_LOG_NORMALIZERS = (
    (r"(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "<uuid>"),
    (r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b", "<ip>"),
    (
        r"(?i)(^|[^0-9a-z_:])((?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}"
        r"|(?:[0-9a-f]{1,4}:){1,7}:(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,6})?"
        r"|::[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,6})",
        r"\1<ipv-six>",
    ),
    (r"(?i)0x[0-9a-f]+|[0-9a-f]{8,}", "<hex>"),
    (r"\d+", "<n>"),
    (r"\s+", " "),
)

HOST_LOG_SOURCES_SQL = (
    "SELECT host, source, max(minute) AS last_seen, "
    "sumIf(lines, minute >= now() - INTERVAL 24 HOUR) AS lines_24h "
    "FROM ssdf.host_log_senders WHERE minute >= now() - INTERVAL 7 DAY "
    "GROUP BY host, source ORDER BY host, source LIMIT 1000"
)


def _ch_literal(text: str) -> str:
    """Render a constant as a ClickHouse string literal (backslashes doubled)."""
    return "'" + text.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _host_log_pattern_expr() -> str:
    expr = "message"
    for regex, replacement in _HOST_LOG_NORMALIZERS:
        expr = f"replaceRegexpAll({expr}, {_ch_literal(regex)}, {_ch_literal(replacement)})"
    return f"substringUTF8(trimBoth(replaceAll({expr}, '<ipv-six>', '<ip6>')), 1, 300)"


def _host_log_lines(since, until, min_severity, host, params):
    """Filtered, kind-tagged, normalized ssdf.host_logs lines (inner query of both builders)."""
    if isinstance(min_severity, bool) or not isinstance(min_severity, int):
        raise BuilderError("min_severity must be an integer 0-7")
    if not 0 <= min_severity <= 7:
        raise BuilderError("min_severity must be between 0 and 7")
    params["min_severity"] = min_severity
    conditions = _window(since, until, params)
    if host is not None:
        if not isinstance(host, str) or not host:
            raise BuilderError("host must be a non-empty string")
        params["host"] = host
        conditions.append("host = {host:String}")
    kind_expr = (
        "multiIf(unit LIKE 'systemd-coredump%' AND position(message, 'dumped core') > 0, 'crash', "
        "unit IN ('systemd', 'init.scope') "
        "AND match(message, 'Failed with result|entered failed state'), 'unit_failed', 'error')"
    )
    return (
        f"SELECT host, source, unit, severity, timestamp, message, {kind_expr} AS kind, "
        f"{_host_log_pattern_expr()} AS pattern "
        f"FROM ssdf.host_logs WHERE {' AND '.join(conditions)} "
        "AND (kind != 'error' OR severity <= {min_severity:UInt8})"
    )


def build_host_log_patterns(since=None, until=None, min_severity=3, limit=300, offset=0, host=None):
    """Normalized message patterns from ssdf.host_logs over a window, one page at a time.

    Order is total, so offset paging is stable for a fixed since/until: kind (crash,
    unit_failed, error), then count desc, then host, unit, pattern, source.
    ``total_patterns`` (count() OVER ()) is the group count before LIMIT/OFFSET. Lines of
    kind crash/unit_failed are kept at any severity; plain errors need severity <= min_severity.
    """
    if isinstance(offset, bool) or not isinstance(offset, int):
        raise BuilderError(f"offset must be an integer 0-{HOST_LOG_PATTERNS_MAX_OFFSET}")
    if not 0 <= offset <= HOST_LOG_PATTERNS_MAX_OFFSET:
        raise BuilderError(f"offset must be between 0 and {HOST_LOG_PATTERNS_MAX_OFFSET}")
    params: dict = {}
    inner = _host_log_lines(since, until, min_severity, host, params)
    limit = _clamp(limit, 1, HOST_LOG_PATTERNS_MAX_LIMIT)
    # worst_severity/occurrences avoid aliases that shadow columns/functions; tools.py renames.
    sql = (
        "SELECT host, source, unit, kind, pattern, min(severity) AS worst_severity, "
        "count() AS occurrences, min(timestamp) AS first_seen, max(timestamp) AS last_seen, "
        "any(message) AS sample, count() OVER () AS total_patterns "
        f"FROM ({inner}) GROUP BY host, source, unit, kind, pattern "
        "ORDER BY indexOf(['crash', 'unit_failed', 'error'], kind), occurrences DESC, "
        "host, unit, pattern, source "
        f"LIMIT {limit} OFFSET {offset}"
    )
    return sql, params


def build_host_log_patterns_count(since=None, until=None, min_severity=3, host=None):
    """Pattern-group count for the same filters; used when a page past the end has no rows."""
    params: dict = {}
    inner = _host_log_lines(since, until, min_severity, host, params)
    sql = (
        "SELECT count() AS total_patterns FROM "
        f"(SELECT 1 FROM ({inner}) GROUP BY host, source, unit, kind, pattern)"
    )
    return sql, params


def build_host_log_sources():
    """Per-(host, source) sender liveness from the SummingMergeTree minute rollup."""
    return HOST_LOG_SOURCES_SQL, {}
