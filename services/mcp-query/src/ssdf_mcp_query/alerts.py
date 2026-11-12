"""recent_alerts: alert-class rows from ssdf.events with normalized severity.

Severity normalization lives HERE (SSDF owns the schema knowledge): ssdf.events
has no severity column; each provider hides severity in ext differently.
Scale: critical=4, high=3, medium=2, low=1.
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
    "ext['syslog.severity'] != '', "
    "multiIf(toInt32OrZero(ext['syslog.severity']) <= 2, 4, "
    "toInt32OrZero(ext['syslog.severity']) = 3, 3, "
    "toInt32OrZero(ext['syslog.severity']) = 4, 2, 1), "
    "2)"
)

# Junos screen (RT_SCREEN) rows carry this literal instead of a rule name.
NO_RULE_NAMES = ("", "N/A")


def normalize_severity(provider: str, event_kind: str, ext: dict) -> tuple[str, int] | None:
    """Return (severity_label, severity_num) or None if not an alert-class row.

    Args:
        provider: event_provider value (e.g. "unifi", "paloalto", "juniper")
        event_kind: event_kind value (e.g. "alert", "event")
        ext: the ext Map from ssdf.events

    Returns:
        (severity_label, severity_num) tuple or None if not alert-class
    """
    # UniFi IPS (Suricata): 1 is WORST, inverted scale
    # Vector.toml line 519: if sev != "" { ext = set!(ext, ["unifi.ips.severity"], sev) }
    if "unifi.ips.severity" in ext:
        sev = ext["unifi.ips.severity"]
        if sev == "1":
            return ("critical", 4)
        elif sev == "2":
            return ("high", 3)
        # 3 and anything else → medium
        return ("medium", 2)

    # PAN-OS threat: string severity values
    if PAN_SEVERITY_KEY in ext:
        s = ext[PAN_SEVERITY_KEY].lower()
        if s in SEVERITY_NUM:
            return (s, SEVERITY_NUM[s])
        # informational → low, anything unknown → medium
        return ("low", 1) if s == "informational" else ("medium", 2)

    # Syslog numeric severity: 0-7, lower is worse (RFC 5424)
    if "syslog.severity" in ext:
        n = int(ext["syslog.severity"])
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
    params = {
        "since": parse_time(since),
        "limit": max(1, min(int(limit), 2000)),
        "floor": SEVERITY_NUM.get(min_severity, 3),  # default to high if unknown
    }

    # Alert-class gate: explicit event_kind IN (alert) OR has UniFi IPS signature
    # OR has PAN severity ext key (PAN THREAT logs keep event_kind='event')
    # `timestamp` is QUALIFIED: the SELECT below aliases `toString(timestamp) AS
    # timestamp`, and an unqualified reference binds to that String alias rather
    # than the real DateTime column, making the window a lexical string compare.
    # It happens to agree today only because the bound is a datetime rendered in
    # the same layout toString() emits; qualifying removes the dependency on that
    # coincidence (see build_subgraph_sql, where the layouts differed and a
    # same-day window silently returned nothing).
    where = [
        "events.timestamp >= %(since)s",
        "(event_kind IN %(kinds)s OR ext['unifi.ips.signature'] != '' OR ext['panw.panos.severity'] != '')",
        SEVERITY_NUM_SQL + " >= %(floor)s",
    ]
    params["kinds"] = tuple(ALERT_KINDS)

    if providers:
        params["providers"] = tuple(p.strip() for p in providers.split(",") if p.strip())
        where.append("event_provider IN %(providers)s")

    sql = (
        "SELECT event_id, toString(timestamp) AS timestamp, event_provider, "
        "event_kind, event_action, rule_name, source_ip, source_port, destination_ip, "
        "destination_port, observer_hostname, observer_ingress_zone, "
        "observer_egress_zone, ext "
        "FROM ssdf.events WHERE "
        + " AND ".join(where)
        + " ORDER BY events.timestamp DESC LIMIT %(limit)s"
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
            rule_name = r.get("rule_name") or ""
            sig = (
                ext.get("unifi.ips.signature")
                or (rule_name if rule_name not in NO_RULE_NAMES else "")
                or r.get("event_action")
                or r.get("event_kind")
            )

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
                        if k.startswith(("unifi.ips.", "panw.", "syslog."))
                    },
                }
            )

        return {
            "rows": rows,
            "row_count": len(rows),
            "truncated": len(result.get("rows", [])) >= params["limit"],
        }
