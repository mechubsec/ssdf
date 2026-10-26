"""Run every SQL builder against a REAL ClickHouse holding known rows.

Why this file exists
--------------------

The unit suites stub ClickHouse with fakes whose ``run()`` matches on a
substring of the SQL and returns canned rows. That validates "the code called
ClickHouse", never "the SQL is correct". Every ClickHouse bug this project has
shipped got through a green unit suite:

- ``toString(col) AS col`` shadowing the real column, so a datetime filter
  became a lexical string compare (M6a, and again in 2026-08-26's same-day
  window bug, where a short window silently returned 0 rows instead of 631).
- ``events.timestamp`` being ``DateTime64(3,'UTC')`` and rejecting a raw ISO
  ``+00:00`` string, a live ``TYPE_MISMATCH`` (M12 ``observed_by``).
- ``load_subgraph`` deriving nodes FROM edges, so an isolated firewall node with
  zero edges was invisible -- masked by a stub that returned it anyway (M12).

None of those are detectable without a real server: they are the server's
semantics, not the code's. So this module executes each builder's real SQL
against a real ClickHouse and asserts what comes back.

Marked ``contract`` rather than ``integration``: it needs ONLY a throwaway
ClickHouse -- no lab, no MCP endpoints, no credentials, and it writes nothing
anyone else reads. CI runs it against a service container on every pull request;
``integration`` stays lab-only. Fixtures are written under their own tenant so a
run cannot disturb other data if pointed somewhere shared.
"""

from __future__ import annotations

import datetime as dt
import os
import uuid

import pytest

pytestmark = pytest.mark.contract

clickhouse_connect = pytest.importorskip("clickhouse_connect")

from ssdf_common.config import Secret  # noqa: E402
from ssdf_mcp_query.alerts import build_recent_alerts_sql  # noqa: E402
from ssdf_mcp_query.builders import (  # noqa: E402
    build_host_log_patterns,
    build_host_log_patterns_count,
    build_host_log_sources,
    build_query_flows,
    build_top_talkers,
)
from ssdf_mcp_query.clickhouse import ClickHouseClient  # noqa: E402
from ssdf_mcp_query.config import Config  # noqa: E402
from ssdf_mcp_query.entitystore import (  # noqa: E402
    build_alerts_for_pair_sql,
    build_comm_edges_multi_sql,
    build_comm_edges_sql,
    build_configured_governed_sql,
    build_entities_by_id_sql,
    build_entities_match_sql,
    build_entity_match_sql,
    build_firewall_match_sql,
    build_governed_by_sql,
    build_observers_for_ips_sql,
)
from ssdf_mcp_query.graphstore import (  # noqa: E402
    build_node_match_sql,
    build_nodes_by_attr_sql,
    build_nodes_by_id_sql,
    build_subgraph_sql,
)
from ssdf_mcp_query.liveness_tools import build_recent_observer_hostnames_sql  # noqa: E402

TENANT = "t_contract"

# A window START that shares its UTC date with the fixture rows. This is the
# case the unit suites never exercised and the one the same-day window bug hid
# in: `toString()` renders "YYYY-MM-DD HH:MM:SS.mmm" while callers pass
# isoformat's "YYYY-MM-DDTHH:MM:SS.mmm+00:00". Those diverge at offset 10
# (' ' 0x20 vs 'T' 0x54), so a lexical compare drops every row sharing the date.
_NOW = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
_TODAY_EARLY = _NOW.replace(hour=0, minute=5, second=0)
_TODAY_LATE = _NOW.replace(hour=23, minute=55, second=0)


def _iso(value: dt.datetime) -> str:
    """Exactly what the tools' own `_since()` helpers produce."""
    return value.isoformat(timespec="milliseconds")


# Inserted as tz-AWARE datetime objects, never strings. A naive string is
# reinterpreted in the server's local zone on insert, which silently shifted
# these fixtures onto the NEXT UTC date and made the same-day assertions below
# vacuous -- they passed against a deliberately broken builder.


@pytest.fixture(scope="module")
def raw():
    """A writable driver client, or skip when no contract ClickHouse is offered."""
    host = os.environ.get("CH_CONTRACT_HOST")
    if not host:
        pytest.skip("set CH_CONTRACT_HOST to run the SQL contract suite")
    client = clickhouse_connect.get_client(
        host=host,
        port=int(os.environ.get("CH_CONTRACT_PORT", "8123")),
        username=os.environ.get("CH_CONTRACT_USER", "default"),
        password=os.environ.get("CH_CONTRACT_PASSWORD", ""),
        database="ssdf",
    )
    client.query("SELECT 1")
    return client


@pytest.fixture(scope="module")
def ch(raw):
    """The REAL ClickHouseClient -- the same path production queries take."""
    return ClickHouseClient(
        Config(
            ch_host=os.environ.get("CH_CONTRACT_HOST", ""),
            ch_port=int(os.environ.get("CH_CONTRACT_PORT", "8123")),
            ch_user=os.environ.get("CH_CONTRACT_USER", "default"),
            ch_password=Secret(os.environ.get("CH_CONTRACT_PASSWORD", "")),
            ch_database="ssdf",
            mcp_bind="127.0.0.1",
            mcp_port=0,
            tokens={},
        )
    )


@pytest.fixture(scope="module", autouse=True)
def seed(raw):
    """Known rows, all timestamped TODAY so same-day windows are exercised."""
    early, late = _TODAY_EARLY, _TODAY_LATE

    raw.command(f"DELETE FROM ssdf.events WHERE tenant_id = '{TENANT}'")
    raw.command(f"DELETE FROM ssdf.graph_nodes WHERE tenant_id = '{TENANT}'")
    raw.command(f"DELETE FROM ssdf.graph_edges WHERE tenant_id = '{TENANT}'")
    raw.command(f"DELETE FROM ssdf.entities WHERE tenant_id = '{TENANT}'")
    raw.command(f"DELETE FROM ssdf.entity_edges WHERE tenant_id = '{TENANT}'")

    raw.insert(
        "ssdf.graph_nodes",
        [
            # A connected host, and a firewall device carrying NO edges at all.
            # The isolated one is the M12 regression: load_subgraph derives nodes
            # from edges, so a 0-edge node is invisible to it and must be found
            # by build_nodes_by_attr_sql instead.
            ["host-a", TENANT, "host", "host-a", {"ip": "203.0.113.10"}, early, late, {}],
            ["host-b", TENANT, "host", "host-b", {"ip": "203.0.113.20"}, early, late, {}],
            [
                "device:fw-contract",
                TENANT,
                "device",
                "fw-contract",
                {"name": "fw-contract"},
                early,
                late,
                {"role": "firewall"},
            ],
        ],
        column_names=[
            "node_id",
            "tenant_id",
            "kind",
            "name",
            "identifiers",
            "first_seen",
            "last_seen",
            "attrs",
        ],
    )
    raw.insert(
        "ssdf.graph_edges",
        [
            [
                "edge-ab",
                TENANT,
                "host-a",
                "host-b",
                "communicated_with",
                "flow",
                early,
                late,
                1.0,
                {},
            ]
        ],
        column_names=[
            "edge_id",
            "tenant_id",
            "src_id",
            "dst_id",
            "edge_type",
            "layer",
            "first_seen",
            "last_seen",
            "confidence",
            "attrs",
        ],
    )
    raw.insert(
        "ssdf.entities",
        [
            [
                "ent-a",
                TENANT,
                "asset",
                "host-a",
                {"ip": "203.0.113.10"},
                "observed",
                1.0,
                early,
                late,
                {},
            ],
            [
                "ent-fw",
                TENANT,
                "firewall",
                "fw-contract",
                {"device_name": "fw-contract", "provider": "juniper"},
                "configured",
                1.0,
                early,
                late,
                {},
            ],
        ],
        column_names=[
            "entity_id",
            "tenant_id",
            "kind",
            "name",
            "identifiers",
            "source",
            "confidence",
            "first_seen",
            "last_seen",
            "attrs",
        ],
    )
    raw.insert(
        "ssdf.entity_edges",
        [
            [
                "ee-comm",
                TENANT,
                "ent-a",
                "ent-fw",
                "communicated_with",
                "observed",
                1.0,
                early,
                late,
                {},
            ],
            [
                "ee-gov",
                TENANT,
                "ent-fw",
                "ent-a",
                "governed_by",
                "configured",
                1.0,
                early,
                late,
                {},
            ],
        ],
        column_names=[
            "edge_id",
            "tenant_id",
            "src_id",
            "dst_id",
            "edge_type",
            "source",
            "confidence",
            "first_seen",
            "last_seen",
            "attrs",
        ],
    )
    raw.insert(
        "ssdf.events",
        [
            # A UniFi IPS alert, and a flow the firewall observed.
            [
                late,
                str(uuid.uuid4()),
                TENANT,
                "alert",
                ["intrusion_detection"],
                "ips_alert",
                "success",
                "unifi",
                "203.0.113.10",
                1234,
                "203.0.113.20",
                443,
                "tcp",
                "",
                "",
                "",
                {"unifi.ips.signature": "ET SCAN contract", "unifi.ips.severity": "high"},
                "",
            ],
            [
                late,
                str(uuid.uuid4()),
                TENANT,
                "event",
                ["network"],
                "flow_close",
                "success",
                "juniper",
                "203.0.113.10",
                1234,
                "203.0.113.20",
                443,
                "tcp",
                "allow-any",
                "trust",
                "untrust",
                {},
                "fw-contract",
            ],
        ],
        column_names=[
            "timestamp",
            "event_id",
            "tenant_id",
            "event_kind",
            "event_category",
            "event_action",
            "event_outcome",
            "event_provider",
            "source_ip",
            "source_port",
            "destination_ip",
            "destination_port",
            "network_transport",
            "rule_name",
            "observer_ingress_zone",
            "observer_egress_zone",
            "ext",
            "observer_hostname",
        ],
    )
    return None


# --- Every builder must produce SQL the server actually accepts --------------
#
# A FakeCH cannot catch a misspelled column, a wrong Map key syntax, or a
# parameter type ClickHouse rejects -- it never parses the SQL. Executing each
# builder is the broad net; the named tests below pin specific past bugs.

_SINCE_SAME_DAY = _iso(_TODAY_EARLY)
_IPS = ["203.0.113.10", "203.0.113.20"]

ALL_BUILDERS = {
    "node_match": lambda: build_node_match_sql("203.0.113.10", TENANT),
    "subgraph": lambda: build_subgraph_sql(_SINCE_SAME_DAY, TENANT),
    "nodes_by_id": lambda: build_nodes_by_id_sql(["host-a"], TENANT),
    "nodes_by_attr_role": lambda: build_nodes_by_attr_sql("firewall", None, TENANT),
    "nodes_by_attr_kind": lambda: build_nodes_by_attr_sql(None, "device", TENANT),
    "entity_match": lambda: build_entity_match_sql("203.0.113.10", TENANT),
    "entities_match": lambda: build_entities_match_sql("203.0.113.10", TENANT),
    "comm_edges": lambda: build_comm_edges_sql("ent-a", "ent-fw", _SINCE_SAME_DAY, TENANT),
    "comm_edges_multi": lambda: build_comm_edges_multi_sql(
        ["ent-a"], ["ent-fw"], _SINCE_SAME_DAY, TENANT
    ),
    "governed_by": lambda: build_governed_by_sql(["ee-comm"], TENANT),
    "entities_by_id": lambda: build_entities_by_id_sql(["ent-a"], TENANT),
    "firewall_match": lambda: build_firewall_match_sql(["fw-contract"], TENANT),
    "configured_governed": lambda: build_configured_governed_sql(["ent-fw"], TENANT),
    "alerts_for_pair": lambda: build_alerts_for_pair_sql(_IPS, _SINCE_SAME_DAY, TENANT),
    "observers_for_ips": lambda: build_observers_for_ips_sql(_IPS, _SINCE_SAME_DAY, TENANT),
    "recent_alerts": lambda: build_recent_alerts_sql("now-24h", "low", "", 10),
    "recent_observer_hostnames": lambda: build_recent_observer_hostnames_sql(
        _SINCE_SAME_DAY, TENANT
    ),
    "query_flows": lambda: build_query_flows(limit=10),
    "top_talkers": lambda: build_top_talkers(limit=10),
    "host_log_patterns": lambda: build_host_log_patterns(limit=10, offset=5, host="contract-a"),
    "host_log_patterns_count": lambda: build_host_log_patterns_count(host="contract-a"),
    "host_log_sources": build_host_log_sources,
}


@pytest.mark.parametrize("name", sorted(ALL_BUILDERS))
def test_builder_sql_is_accepted_by_clickhouse(ch, name):
    """The SQL parses, the columns exist, and the parameter types bind."""
    sql, params = ALL_BUILDERS[name]()
    result = ch.run(sql, params)
    assert "rows" in result, f"{name}: no rows key in {result!r}"


# --- host_log_patterns paging ------------------------------------------------
#
# host_logs has no tenant column, so these rows use their own contract-* hosts.
# The window is pinned and absolute, as a paging caller must pin it.

_HL_SINCE = _iso(_NOW - dt.timedelta(hours=2))
_HL_UNTIL = _iso(_NOW)


@pytest.fixture(scope="module")
def host_log_rows(raw):
    raw.command("DELETE FROM ssdf.host_logs WHERE host LIKE 'contract-%'")
    at = _NOW - dt.timedelta(hours=1)
    lines = (
        [("contract-b", "journald", "systemd-coredump@1-2-3.service", 2, "Process 42 dumped core")]
        + [("contract-a", "journald", "systemd", 5, "x.service: Failed with result 'exit-code'")]
        * 2
        + [("contract-a", "syslog", "sshd", 3, f"error {i}") for i in range(5)]
        + [("contract-a", "syslog", "cron", 3, "tick")] * 3
        + [("contract-b", "syslog", "cron", 3, "tick")] * 3
        + [("contract-a", "journald", "app", 3, "dup")] * 2
        + [("contract-a", "syslog", "app", 3, "dup")] * 2
        + [("contract-a", "syslog", "noise", 6, "info only")]  # severity 6 > min_severity 3
    )
    raw.insert(
        "ssdf.host_logs",
        [[at, host, source, unit, sev, msg, msg] for host, source, unit, sev, msg in lines],
        column_names=["timestamp", "host", "source", "unit", "severity", "message", "raw"],
    )
    yield
    raw.command("DELETE FROM ssdf.host_logs WHERE host LIKE 'contract-%'")


def _hl_page(ch, **kw):
    sql, params = build_host_log_patterns(since=_HL_SINCE, until=_HL_UNTIL, **kw)
    return ch.run(sql, params)["rows"]


def test_host_log_patterns_order_and_offset_paging(ch, host_log_rows):
    full = _hl_page(ch, limit=100)
    got = [(r["kind"], r["host"], r["unit"], r["source"], int(r["occurrences"])) for r in full]
    assert got == [
        ("crash", "contract-b", "systemd-coredump@1-2-3.service", "journald", 1),
        ("unit_failed", "contract-a", "systemd", "journald", 2),
        ("error", "contract-a", "sshd", "syslog", 5),  # "error <n>" x5
        ("error", "contract-a", "cron", "syslog", 3),  # count tie: host breaks it
        ("error", "contract-b", "cron", "syslog", 3),
        ("error", "contract-a", "app", "journald", 2),  # host/unit/pattern tie: source breaks it
        ("error", "contract-a", "app", "syslog", 2),
    ]
    assert {int(r["total_patterns"]) for r in full} == {7}
    paged = [r for off in (0, 3, 6) for r in _hl_page(ch, limit=3, offset=off)]
    assert [(r["host"], r["source"], r["unit"], r["kind"], r["pattern"]) for r in paged] == [
        (r["host"], r["source"], r["unit"], r["kind"], r["pattern"]) for r in full
    ]
    assert _hl_page(ch, limit=3, offset=7) == []  # past the end: no row carries the total
    sql, params = build_host_log_patterns_count(since=_HL_SINCE, until=_HL_UNTIL)
    assert int(ch.run(sql, params)["rows"][0]["total_patterns"]) == 7
    only_b = _hl_page(ch, limit=100, host="contract-b")
    assert [(r["kind"], r["unit"]) for r in only_b] == [
        ("crash", "systemd-coredump@1-2-3.service"),
        ("error", "cron"),
    ]
    assert {int(r["total_patterns"]) for r in only_b} == {2}


# --- Regressions, each pinned to a bug that shipped -------------------------


def test_subgraph_same_day_window_returns_the_edge(ch):
    """The 2026-08-26 bug: a same-day window silently returned nothing.

    The edge's last_seen shares a UTC date with the window start, which is what
    a lexical string compare drops. Live, this returned 0 of 631 edges.
    """
    sql, params = build_subgraph_sql(_SINCE_SAME_DAY, TENANT)
    rows = ch.run(sql, params)["rows"]
    assert any(r["edge_id"] == "edge-ab" for r in rows), (
        "a same-day window dropped the edge -- the window bound is being compared "
        "as a string against the toString() alias, not as a datetime"
    )


def test_alerts_for_pair_same_day_window_returns_the_alert(ch):
    """Same defect class, reached through explain_access's `detections`."""
    sql, params = build_alerts_for_pair_sql(_IPS, _SINCE_SAME_DAY, TENANT)
    rows = ch.run(sql, params)["rows"]
    assert len(rows) >= 1, "a same-day window dropped the UniFi IPS detection"


def test_observers_for_ips_accepts_an_iso_offset_bound(ch):
    """M12: events.timestamp is DateTime64(3,'UTC') and rejected a raw ISO bound.

    The failure was a live TYPE_MISMATCH, invisible to a stub that never typed
    its columns.
    """
    sql, params = build_observers_for_ips_sql(_IPS, _SINCE_SAME_DAY, TENANT)
    rows = ch.run(sql, params)["rows"]
    assert [r["observer_hostname"] for r in rows] == ["fw-contract"]


def test_nodes_by_attr_finds_a_firewall_with_no_edges(ch):
    """M12: an isolated node is invisible to load_subgraph, which derives nodes
    from edges. `fw-contract` deliberately has zero edges."""
    sql, params = build_nodes_by_attr_sql("firewall", None, TENANT)
    rows = ch.run(sql, params)["rows"]
    assert [r["node_id"] for r in rows] == ["device:fw-contract"]


def test_datetime_columns_come_back_as_strings_not_lexical_traps(ch):
    """The builders alias `toString(...)`; confirm the alias renders the layout
    the code elsewhere assumes, so a future format change is caught here."""
    sql, params = build_node_match_sql("203.0.113.10", TENANT)
    rows = ch.run(sql, params)["rows"]
    assert rows, "fixture node not found"
    last_seen = rows[0]["last_seen"]
    assert isinstance(last_seen, str)
    # "YYYY-MM-DD HH:MM:SS..." -- a space at offset 10, never a 'T'.
    assert last_seen[10] == " ", f"unexpected datetime rendering: {last_seen!r}"
