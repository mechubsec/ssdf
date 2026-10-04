"""Daily rollup of ssdf.events into ssdf.flow_tuples_daily (MEC-1639, task B of
MEC-570, per the change-impact-scope doc on MEC-986 §1.3/§2.1).

Deterministic aggregation only -- no model involvement, matching the house
rule that deterministic code decides. Run periodically (e.g. a daily systemd
timer) as the least-privilege `ssdf_flowtuples` identity created by
infra/clickhouse/025_flow_tuples_daily.sql:

    CH_USER=ssdf_flowtuples python -m ssdf_policy.flow_tuples_rollup
"""

from __future__ import annotations

import datetime
import logging
import os

import clickhouse_connect

from .chwriter import client_kwargs
from .config import load_config

log = logging.getLogger("ssdf_policy.flow_tuples_rollup")

# The RT_FLOW field Junos puts the post-DNAT/pre-SNAT destination under.
# Verified from code (ext is built wholesale from the RT_FLOW key=value
# fields, infra/vector/vector.toml `"ext": map_values(fields)`) and from the
# sample RT_FLOW line in docs/superpowers/plans/2026-06-05-ssdf-srx-ingest.md.
# NOT verified against a live device (doc §1.3) -- that is a read-only log
# look on vsrx-ci, still outstanding.
JUNOS_NAT_DEST_KEY = "nat-destination-address"

# The post-app-shift App-ID PAN-OS logs; vector.toml sets this unconditionally
# for TRAFFIC/THREAT records (panos_ecs transform).
PANOS_APP_KEY = "panw.panos.application"

# One row per session end/deny, per vendor (doc §1.3); dropping
# flow_session_create/flow_start avoids double-counting a session.
JUNOS_EVENT_ACTIONS = ("flow_session_close", "flow_session_deny")
PANOS_EVENT_ACTIONS = ("flow_end", "flow_deny", "flow_drop")
EVENT_ACTIONS = JUNOS_EVENT_ACTIONS + PANOS_EVENT_ACTIONS

FLOW_TUPLES_COLUMNS = [
    "tenant_id",
    "observer_hostname",
    "ingress_zone",
    "egress_zone",
    "day",
    "src_ip",
    "dst_ip_eff",
    "transport",
    "dst_port",
    "app",
    "provider",
    "sessions",
    "bytes",
    "first_seen",
    "last_seen",
    "logged_rules",
    "outcomes",
]


def effective_destination_ip(
    provider: str, destination_ip: str | None, ext: dict[str, str]
) -> str | None:
    """The destination IP the policy engine actually evaluated (doc §1.3).

    Junos applies static/destination NAT before the policy lookup, so the
    post-DNAT address is what matched, not the pre-DNAT `destination_ip`
    ssdf.events records. PAN-OS matches security policy on pre-NAT
    addresses, so `destination_ip` is already the effective value there.
    """
    if provider == "juniper":
        nat_dst = ext.get(JUNOS_NAT_DEST_KEY, "")
        if nat_dst and nat_dst != "0.0.0.0":
            return nat_dst
    return destination_ip


def effective_app(provider: str, ext: dict[str, str]) -> str:
    """The logged application, for vendors/fields where it's meaningful.

    Only PAN-OS logs a resolved App-ID; Junos's application match is on
    protocol/port sets the typed `transport`/`dst_port` columns already
    cover, so it has no equivalent field here.
    """
    if provider == "paloalto":
        return ext.get(PANOS_APP_KEY, "")
    return ""


def compute_window(
    now: datetime.datetime, lookback_days: int
) -> tuple[datetime.datetime, datetime.datetime]:
    """Whole-day window ending at the current start of day.

    Recomputing the last `lookback_days` COMPLETE days (not just the newest
    one) means a late-arriving event that lands after the previous run still
    gets rolled up on the next pass; ssdf.flow_tuples_daily is a
    ReplacingMergeTree keyed through `day`, so re-emitting an already-seen
    bucket overwrites it rather than double-counting.
    """
    until = now.replace(hour=0, minute=0, second=0, microsecond=0)
    since = until - datetime.timedelta(days=lookback_days)
    return since, until


def _select_sql() -> str:
    actions = ",".join(f"'{a}'" for a in EVENT_ACTIONS)
    dst_ip_eff = (
        "if(event_provider = 'juniper'"
        f" AND ext['{JUNOS_NAT_DEST_KEY}'] != ''"
        f" AND ext['{JUNOS_NAT_DEST_KEY}'] != '0.0.0.0',"
        f" toIPv4OrNull(ext['{JUNOS_NAT_DEST_KEY}']),"
        " destination_ip) AS dst_ip_eff"
    )
    app = f"if(event_provider = 'paloalto', ext['{PANOS_APP_KEY}'], '') AS app"
    return (
        "SELECT\n"
        "    tenant_id,\n"
        "    observer_hostname,\n"
        "    observer_ingress_zone AS ingress_zone,\n"
        "    observer_egress_zone AS egress_zone,\n"
        "    toDate(timestamp) AS day,\n"
        "    source_ip AS src_ip,\n"
        f"    {dst_ip_eff},\n"
        "    network_transport AS transport,\n"
        "    destination_port AS dst_port,\n"
        f"    {app},\n"
        "    event_provider AS provider,\n"
        "    count() AS sessions,\n"
        "    sum(coalesce(network_bytes, 0)) AS bytes,\n"
        "    min(timestamp) AS first_seen,\n"
        "    max(timestamp) AS last_seen,\n"
        "    groupUniqArray(16)(rule_name) AS logged_rules,\n"
        "    groupUniqArray(4)(event_outcome) AS outcomes\n"
        "FROM ssdf.events\n"
        f"WHERE event_action IN ({actions})\n"
        "  AND timestamp >= {since:DateTime64(3,'UTC')}\n"
        "  AND timestamp < {until:DateTime64(3,'UTC')}\n"
        "GROUP BY tenant_id, observer_hostname, ingress_zone, egress_zone, day,\n"
        "         src_ip, dst_ip_eff, transport, dst_port, app, provider\n"
    )


_SELECT_SQL = _select_sql()


def run_once(client, now: datetime.datetime, lookback_days: int = 3) -> int:
    since, until = compute_window(now, lookback_days)
    result = client.query(
        _SELECT_SQL,
        parameters={"since": since.isoformat(), "until": until.isoformat()},
    )
    rows = [list(row) for row in result.result_rows]
    if not rows:
        return 0
    client.insert("flow_tuples_daily", rows, column_names=FLOW_TUPLES_COLUMNS)
    return len(rows)


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    config = load_config()
    client = clickhouse_connect.get_client(**client_kwargs(config))
    lookback_days = int(os.environ.get("FLOW_TUPLES_LOOKBACK_DAYS", "3"))
    n = run_once(client, datetime.datetime.now(datetime.timezone.utc), lookback_days)
    log.info("flow_tuples_rollup: %d bucket rows upserted", n)


if __name__ == "__main__":
    main()
