"""recent_alerts: alert-class rows from ssdf.events with normalized severity.

Severity normalization lives HERE (SSDF owns the schema knowledge): ssdf.events
has no severity column; each provider hides severity in ext differently.
Scale: critical=4, high=3, medium=2, low=1.

alert_counts: grouped counts over the SAME alert gate, severity expression and
signature expression as recent_alerts, so a noisy source cannot hide how many
alerts of each kind there were behind recent_alerts' row limit.
"""

from __future__ import annotations

from .timeparse import parse_time
from .untrusted_text import UntrustedText

SEVERITY_NUM = {"critical": 4, "high": 3, "medium": 2, "low": 1}

# Pinned from infra/vector/vector.toml live schema (Task 1 Step 1):
# - Line 94 (srx_ecs RT_SCREEN): event_kind = "alert"
# - Line 472 (unifi_ips): ev.event_kind = "alert"
# PAN-OS THREAT logs do NOT set event_kind="alert" — they stay "event" but have
# category ["network","intrusion_detection"], so the WHERE clause gates on the
# ext key (panw.panos.severity) to select them.
ALERT_KINDS = ("alert",)

# PAN severity ext key pinned from vector.toml line 342:
# if sev != "" { ext = set!(ext, ["panw.panos.severity"], sev) }
PAN_SEVERITY_KEY = "panw.panos.severity"

# UniFi controller events (WAN down, device offline, IP conflict...) carry the CEF
# header severity 0-10. Bands follow the common CEF convention: 0-3 low, 4-6 medium,
# 7-8 high, 9-10 critical. UniFi does not document which severity an outage gets.
_UNIFI_EVENT_SEV_SQL = "toInt32OrZero(ext['unifi.event.severity'])"

# normalize_severity as a ClickHouse expression, so the floor applies BEFORE the
# LIMIT. Filtering only in Python let the newest rows below the floor (PAN-OS
# informational system logs, thousands a day) use up the whole LIMIT and the tool
# return nothing. Keep the two in step; normalize_severity still labels each row.
SEVERITY_NUM_SQL = (
    "multiIf("
    "ext['unifi.ips.severity'] != '', "
    "multiIf(ext['unifi.ips.severity'] = '1', 4, ext['unifi.ips.severity'] = '2', 3, 2), "
    "ext['panw.panos.severity'] != '', "
    "multiIf(lower(ext['panw.panos.severity']) = 'critical', 4, "
    "lower(ext['panw.panos.severity']) = 'high', 3, "
    "lower(ext['panw.panos.severity']) = 'medium', 2, "
    "lower(ext['panw.panos.severity']) IN ('low', 'informational'), 1, 2), "
    "ext['unifi.event.severity'] != '', "
    f"multiIf({_UNIFI_EVENT_SEV_SQL} <= 3, 1, {_UNIFI_EVENT_SEV_SQL} <= 6, 2, "
    f"{_UNIFI_EVENT_SEV_SQL} <= 8, 3, 4), "
    "ext['syslog.severity'] != '', "
    "multiIf(toInt32OrZero(ext['syslog.severity']) <= 2, 4, "
    "toInt32OrZero(ext['syslog.severity']) = 3, 3, "
    "toInt32OrZero(ext['syslog.severity']) = 4, 2, 1), "
    "2)"
)

# Junos screen (RT_SCREEN) rows carry this literal instead of a rule name.
NO_RULE_NAMES = ("", "N/A")

# How an alert is named: UniFi IPS signature, else rule name (unless empty/N/A),
# else event action, else event kind. ONE definition, used by recent_alerts and
# alert_counts, in SQL so grouped counts are exact.
SIGNATURE_SQL = (
    "multiIf(ext['unifi.ips.signature'] != '', ext['unifi.ips.signature'], "
    f"rule_name NOT IN {NO_RULE_NAMES!r}, rule_name, "
    "event_action != '', event_action, event_kind)"
)

# Alert-class gate: explicit event_kind IN (alert) OR has UniFi IPS signature
# OR has PAN severity ext key (PAN THREAT logs keep event_kind='event')
ALERT_GATE_SQL = (
    "(event_kind IN %(kinds)s OR ext['unifi.ips.signature'] != '' "
    "OR ext['panw.panos.severity'] != '')"
)

# Max (provider, observer, signature, severity) groups alert_counts returns.
MAX_COUNT_GROUPS = 500


def _int_or_zero(value: str) -> int:
    """Mirror ClickHouse toInt32OrZero for the severity strings."""
    try:
        return int(value)
    except ValueError:
        return 0


def normalize_severity(provider: str, event_kind: str, ext: dict) -> tuple[str, int] | None:
    """Return (severity_label, severity_num) or None if not an alert-class row.

    Args:
        provider: event_provider value (e.g. "unifi", "paloalto", "juniper")
        event_kind: event_kind value (e.g. "alert", "event")
        ext: the ext Map from ssdf.events

    Returns:
        (severity_label, severity_num) tuple or None if not alert-class
    """
    # Empty values count as absent, like the SQL `!= ''` guards in SEVERITY_NUM_SQL.
    # UniFi IPS (Suricata): 1 is WORST, inverted scale
    ips_sev = ext.get("unifi.ips.severity")
    if ips_sev:
        if ips_sev == "1":
            return ("critical", 4)
        if ips_sev == "2":
            return ("high", 3)
        # 3 and anything else -> medium
        return ("medium", 2)

    # PAN-OS threat: string severity values
    pan_sev = ext.get(PAN_SEVERITY_KEY)
    if pan_sev:
        s = pan_sev.lower()
        if s in SEVERITY_NUM:
            return (s, SEVERITY_NUM[s])
        # informational -> low, anything unknown -> medium
        return ("low", 1) if s == "informational" else ("medium", 2)

    # UniFi controller event: CEF severity 0-10 (bands documented at _UNIFI_EVENT_SEV_SQL)
    event_sev = ext.get("unifi.event.severity")
    if event_sev:
        n = _int_or_zero(event_sev)
        if n <= 3:
            return ("low", 1)
        if n <= 6:
            return ("medium", 2)
        if n <= 8:
            return ("high", 3)
        return ("critical", 4)

    # Syslog numeric severity: 0-7, lower is worse (RFC 5424)
    syslog_sev = ext.get("syslog.severity")
    if syslog_sev:
        n = _int_or_zero(syslog_sev)
        if n <= 2:
            return ("critical", 4)
        if n == 3:
            return ("high", 3)
        if n == 4:
            return ("medium", 2)
        return ("low", 1)

    # Alert-class row but unmapped ext → default medium
    if event_kind in ALERT_KINDS:
        return ("medium", 2)

    # Not an alert-class row
    return None


def _alert_where(since: str, min_severity: str, providers: str) -> tuple[list[str], dict]:
    """WHERE clauses + params shared by recent_alerts and alert_counts.

    `timestamp` is QUALIFIED: recent_alerts' SELECT aliases `toString(timestamp) AS
    timestamp`, and an unqualified reference binds to that String alias rather
    than the real DateTime column, making the window a lexical string compare.
    It happens to agree today only because the bound is a datetime rendered in
    the same layout toString() emits; qualifying removes the dependency on that
    coincidence (see build_subgraph_sql, where the layouts differed and a
    same-day window silently returned nothing).
    """
    params = {
        "since": parse_time(since),
        "floor": SEVERITY_NUM.get(min_severity, 3),  # default to high if unknown
        "kinds": tuple(ALERT_KINDS),
    }
    where = [
        "events.timestamp >= %(since)s",
        ALERT_GATE_SQL,
        SEVERITY_NUM_SQL + " >= %(floor)s",
    ]
    if providers:
        params["providers"] = tuple(p.strip() for p in providers.split(",") if p.strip())
        where.append("event_provider IN %(providers)s")
    return where, params


def build_recent_alerts_sql(
    since: str, min_severity: str, providers: str, limit: int
) -> tuple[str, dict]:
    """Build parameterized SQL for recent alert-class events.

    Args:
        since: relative or ISO-8601 time expression (parsed via parse_time)
        min_severity: minimum severity label, applied in SQL so LIMIT counts matching rows
        providers: comma-separated provider names, or empty for all
        limit: max rows to return (clamped to 2000)

    Returns:
        (sql, params) tuple ready for ClickHouseClient.run()
    """
    where, params = _alert_where(since, min_severity, providers)
    params["limit"] = max(1, min(int(limit), 2000))
    sql = (
        "SELECT event_id, toString(timestamp) AS timestamp, event_provider, "
        "event_kind, event_action, rule_name, "
        f"{SIGNATURE_SQL} AS signature, source_ip, source_port, destination_ip, "
        "destination_port, observer_hostname, observer_ingress_zone, "
        "observer_egress_zone, ext "
        "FROM ssdf.events WHERE "
        + " AND ".join(where)
        + " ORDER BY events.timestamp DESC LIMIT %(limit)s"
    )
    return sql, params


def build_alert_counts_sql(since: str, min_severity: str, providers: str) -> tuple[str, dict]:
    """Build SQL counting alert-class events per (provider, observer, signature, severity).

    Same gate, severity expression and signature expression as recent_alerts. Asks
    for MAX_COUNT_GROUPS + 1 groups so the caller can tell the list was cut.
    """
    where, params = _alert_where(since, min_severity, providers)
    params["max_groups"] = MAX_COUNT_GROUPS + 1
    sql = (
        "SELECT event_provider AS provider, observer_hostname AS observer, "
        f"{SIGNATURE_SQL} AS signature, {SEVERITY_NUM_SQL} AS severity_num, "
        "count() AS n, toString(min(events.timestamp)) AS first_seen, "
        "toString(max(events.timestamp)) AS last_seen "
        "FROM ssdf.events WHERE "
        + " AND ".join(where)
        + " GROUP BY provider, observer, signature, severity_num"
        " ORDER BY severity_num DESC, n DESC LIMIT %(max_groups)s"
    )
    return sql, params


class AlertTools:
    """MCP tool surface for alert-class events with normalized severity."""

    def __init__(self, ch):
        self._ch = ch

    def recent_alerts(
        self,
        since: str = "now-24h",
        min_severity: str = "high",
        providers: str = "",
        limit: int = 500,
    ) -> dict:
        """Return recent alert-class events with normalized severity.

        Args:
            since: time window start (ISO-8601 or relative "now-24h" style, default "now-24h")
            min_severity: minimum severity to include (critical|high|medium|low)
            providers: comma-separated provider filter, or empty for all
            limit: max results (default 500, clamped to 2000)

        Returns:
            {rows: [...], row_count: int, truncated: bool}
        """
        sql, params = build_recent_alerts_sql(since, min_severity, providers, limit)
        floor = params["floor"]
        result = self._ch.run(sql, params)

        rows = []
        for r in result.get("rows", []):
            ext = r.get("ext") or {}
            norm = normalize_severity(r.get("event_provider", ""), r.get("event_kind", ""), ext)
            # Skip if not alert-class or below severity floor
            if norm is None or norm[1] < floor:
                continue

            # log-derived; wrapped as UntrustedText
            sig = r.get("signature") or r.get("event_kind")

            rows.append(
                {
                    "event_id": r["event_id"],
                    "timestamp": r["timestamp"],
                    "provider": r["event_provider"],
                    "event_kind": r["event_kind"],
                    "signature": UntrustedText.from_raw(sig).to_response(),
                    "severity": norm[0],
                    "severity_num": norm[1],
                    "source_ip": r.get("source_ip"),
                    "source_port": r.get("source_port"),
                    "destination_ip": r.get("destination_ip"),
                    "destination_port": r.get("destination_port"),
                    "observer": r.get("observer_hostname", ""),
                    "ingress_zone": r.get("observer_ingress_zone", ""),
                    "egress_zone": r.get("observer_egress_zone", ""),
                    "ext_subset": {
                        k: UntrustedText.from_raw(v).to_response()
                        for k, v in ext.items()
                        if k.startswith(("unifi.ips.", "unifi.event.", "panw.", "syslog."))
                    },
                }
            )

        return {
            "rows": rows,
            "row_count": len(rows),
            "truncated": len(result.get("rows", [])) >= params["limit"],
        }

    def alert_counts(
        self, since: str = "now-24h", min_severity: str = "low", providers: str = ""
    ) -> dict:
        """Count alert-class events per (provider, observer, signature, severity).

        Args:
            since: time window start (ISO-8601 or relative "now-24h" style)
            min_severity: minimum severity to include (critical|high|medium|low)
            providers: comma-separated provider filter, or empty for all

        Returns:
            {rows: [{provider, observer, signature, severity, severity_num, count,
            first_seen, last_seen}], row_count, truncated}, worst severity first
            then highest count; at most MAX_COUNT_GROUPS groups.
        """
        sql, params = build_alert_counts_sql(since, min_severity, providers)
        result = self._ch.run(sql, params)
        labels = {num: label for label, num in SEVERITY_NUM.items()}

        raw_rows = result.get("rows", [])
        rows = [
            {
                "provider": r["provider"],
                "observer": UntrustedText.from_raw(r.get("observer") or "").to_response(),
                "signature": UntrustedText.from_raw(r.get("signature") or "").to_response(),
                "severity": labels.get(r["severity_num"], "medium"),
                "severity_num": r["severity_num"],
                "count": r["n"],
                "first_seen": r["first_seen"],
                "last_seen": r["last_seen"],
            }
            for r in raw_rows[:MAX_COUNT_GROUPS]
        ]
        return {
            "rows": rows,
            "row_count": len(rows),
            "truncated": len(raw_rows) > MAX_COUNT_GROUPS,
        }
