"""M16a: infra/clickhouse/008_public_views.sql must never expose the sovereign
graph shape (`SELECT *`) to the ssdf_public tier. It must project an explicit
allowlist -- pseudonymised ids only, no `name`, `identifiers` or `attrs` -- so a
future column added to graph_nodes/graph_edges is sovereign-only by default
instead of silently widening the public view.

Marked ``contract`` (needs only a throwaway ClickHouse, same as
test_sql_contract.py): this file applies 008_public_views.sql itself, with
test-only secrets, against the service container -- it does not depend on the
lab passwords ``test_public_views_integration.py`` needs.
"""

from __future__ import annotations

import os
import pathlib
import urllib.error
import urllib.request

import pytest

pytestmark = pytest.mark.contract

clickhouse_connect = pytest.importorskip("clickhouse_connect")

MIGRATION = (
    pathlib.Path(__file__).resolve().parents[3] / "infra" / "clickhouse" / "008_public_views.sql"
)

# Throwaway values for a throwaway container -- never used against a real deploy.
_DEFINER_PW = "contract-test-definer-pw"
_PUBLIC_PW = "contract-test-public-pw"
_KEY_HI = "11111111111"
_KEY_LO = "22222222222"

# Values that must never reach the public tier in any form.
_SECRET_NAME = "topsecret-lab-hostname"
_SECRET_MAC = "aa:bb:cc:dd:ee:ff"
_SECRET_IP = "203.0.113.9"
_SECRET_ATTR = "should-never-leak"


def _text() -> str:
    return MIGRATION.read_text(encoding="utf-8")


def _statements(sql: str):
    for chunk in sql.split(";"):
        lines = [
            line
            for line in chunk.splitlines()
            if line.strip() and not line.strip().startswith("--")
        ]
        statement = "\n".join(lines).strip()
        if statement:
            yield statement


def _render() -> str:
    rendered = _text()
    for key, value in (
        ("DEFINER_PW", _DEFINER_PW),
        ("PUBLIC_PW", _PUBLIC_PW),
        ("VIEW_PSEUDONYM_KEY_HI", _KEY_HI),
        ("VIEW_PSEUDONYM_KEY_LO", _KEY_LO),
    ):
        rendered = rendered.replace("${%s}" % key, value)
    return rendered


def _apply(base_url: str, sql: str) -> None:
    for statement in _statements(sql):
        try:
            urllib.request.urlopen(
                urllib.request.Request(base_url, data=statement.encode("utf-8"), method="POST"),
                timeout=30,
            ).read()
        except urllib.error.HTTPError as exc:
            raise AssertionError(
                f"applying 008_public_views.sql failed: {exc.read().decode('utf-8', 'replace')}"
            ) from exc


def test_migration_never_selects_star():
    """The historical bug: `SELECT *` over the sovereign tables (M16a)."""
    assert "SELECT *" not in _text()


def test_migration_never_projects_name_identifiers_or_attrs():
    text = _text()
    for leaked_column in ("name", "identifiers", "attrs"):
        assert f", {leaked_column}" not in text
        assert f"    {leaked_column}," not in text
        assert f"    {leaked_column}\n" not in text


@pytest.fixture(scope="module")
def base_url() -> str:
    host = os.environ.get("CH_CONTRACT_HOST")
    if not host:
        pytest.skip("set CH_CONTRACT_HOST to run the SQL contract suite")
    port = int(os.environ.get("CH_CONTRACT_PORT", "8123"))
    return f"http://{host}:{port}/"


@pytest.fixture(scope="module", autouse=True)
def applied(base_url):
    """Seed one sovereign row carrying secrets, then apply the migration under test."""
    node_row = (
        "INSERT INTO ssdf.graph_nodes "
        "(node_id, tenant_id, kind, name, identifiers, first_seen, last_seen, attrs) "
        "VALUES ('contract-test-node-01', 't_contract_views', 'device', "
        f"'{_SECRET_NAME}', {{'mac':'{_SECRET_MAC}','ip':'{_SECRET_IP}'}}, now(), now(), "
        f"{{'note':'{_SECRET_ATTR}'}})"
    )
    edge_row = (
        "INSERT INTO ssdf.graph_edges "
        "(edge_id, tenant_id, src_id, dst_id, edge_type, layer, first_seen, last_seen, confidence, attrs) "
        "VALUES ('contract-test-edge-01', 't_contract_views', 'contract-test-node-01', "
        f"'contract-test-node-02', 'attaches_to', 'l2', now(), now(), 1.0, {{'note':'{_SECRET_ATTR}'}})"
    )
    # a rerun on the same container must not accumulate duplicate seed rows
    for table in ("graph_nodes", "graph_edges"):
        clear = (
            f"ALTER TABLE ssdf.{table} DELETE WHERE tenant_id = 't_contract_views' "
            "SETTINGS mutations_sync = 2"
        )
        urllib.request.urlopen(
            urllib.request.Request(base_url, data=clear.encode("utf-8"), method="POST"),
            timeout=30,
        ).read()
    urllib.request.urlopen(
        urllib.request.Request(base_url, data=node_row.encode("utf-8"), method="POST"), timeout=30
    ).read()
    urllib.request.urlopen(
        urllib.request.Request(base_url, data=edge_row.encode("utf-8"), method="POST"), timeout=30
    ).read()
    _apply(base_url, _render())


@pytest.fixture(scope="module")
def public_client(base_url, applied):
    from urllib.parse import urlparse

    parsed = urlparse(base_url)
    return clickhouse_connect.get_client(
        host=parsed.hostname,
        port=parsed.port,
        username="default",
        password="",
        database="ssdf_public",
    )


def test_public_nodes_view_has_no_raw_columns(public_client):
    columns = {
        row[0] for row in public_client.query("DESCRIBE ssdf_public.graph_nodes").result_rows
    }
    assert columns == {"node_id", "tenant_id", "kind", "first_seen", "last_seen"}


def test_public_edges_view_has_no_raw_columns(public_client):
    columns = {
        row[0] for row in public_client.query("DESCRIBE ssdf_public.graph_edges").result_rows
    }
    assert columns == {
        "edge_id",
        "tenant_id",
        "src_id",
        "dst_id",
        "edge_type",
        "layer",
        "first_seen",
        "last_seen",
        "confidence",
    }


def test_public_nodes_view_leaks_no_secret_and_pseudonymises_the_id(public_client):
    # DISTINCT: ReplacingMergeTree only dedups on merge, so a re-run against a
    # container that already has this fixture's row can see it twice pre-merge.
    rows = public_client.query(
        "SELECT DISTINCT node_id FROM ssdf_public.graph_nodes WHERE tenant_id = 't_contract_views'"
    ).result_rows
    assert len(rows) == 1
    (node_id,) = rows[0]
    assert node_id != "contract-test-node-01"
    dump = str(rows)
    for secret in (_SECRET_NAME, _SECRET_MAC, _SECRET_IP, _SECRET_ATTR, "contract-test-node-01"):
        assert secret not in dump


def test_public_edges_view_join_key_matches_public_node_id(public_client):
    node_id = public_client.query(
        "SELECT DISTINCT node_id FROM ssdf_public.graph_nodes WHERE tenant_id = 't_contract_views'"
    ).result_rows[0][0]
    src_id = public_client.query(
        "SELECT DISTINCT src_id FROM ssdf_public.graph_edges WHERE tenant_id = 't_contract_views'"
    ).result_rows[0][0]
    assert src_id == node_id


def test_public_reader_cannot_read_sovereign_base_tables(base_url):
    from urllib.parse import urlparse

    parsed = urlparse(base_url)
    client = clickhouse_connect.get_client(
        host=parsed.hostname,
        port=parsed.port,
        username="ssdf_public",
        password=_PUBLIC_PW,
        database="ssdf_public",
    )
    client.query("SELECT count() FROM ssdf_public.graph_nodes")
    with pytest.raises(Exception):
        client.query("SELECT count() FROM ssdf.graph_nodes")


# --- F2 (MEC-167): the pseudonym key must never be readable from the public
# tier, in ANY form -- not as a base-table grant, and not embedded as a
# literal in a view's compiled definition (queryable via SHOW CREATE /
# system.tables by anyone holding SELECT on the view).


def test_public_reader_cannot_read_the_pseudonym_key_table(base_url):
    from urllib.parse import urlparse

    parsed = urlparse(base_url)
    client = clickhouse_connect.get_client(
        host=parsed.hostname,
        port=parsed.port,
        username="ssdf_public",
        password=_PUBLIC_PW,
        database="ssdf_public",
    )
    with pytest.raises(Exception):
        client.query("SELECT * FROM ssdf.view_pseudonym_key")


def test_public_view_definitions_do_not_contain_the_pseudonym_key(public_client):
    for table in ("graph_nodes", "graph_edges"):
        create_stmt = public_client.query(f"SHOW CREATE TABLE ssdf_public.{table}").result_rows[0][
            0
        ]
        assert _KEY_HI not in create_stmt
        assert _KEY_LO not in create_stmt

    for (as_select,) in public_client.query(
        "SELECT as_select FROM system.tables WHERE database = 'ssdf_public'"
    ).result_rows:
        assert _KEY_HI not in as_select
        assert _KEY_LO not in as_select


def test_public_views_still_pseudonymise_consistently_via_the_key_table(public_client):
    """The key moved out of the view body (F2); the pseudonymisation and the
    node/edge join-key property (M16a) it must not have regressed."""
    node_id = public_client.query(
        "SELECT DISTINCT node_id FROM ssdf_public.graph_nodes WHERE tenant_id = 't_contract_views'"
    ).result_rows[0][0]
    src_id = public_client.query(
        "SELECT DISTINCT src_id FROM ssdf_public.graph_edges WHERE tenant_id = 't_contract_views'"
    ).result_rows[0][0]
    assert node_id == src_id
    assert node_id != "contract-test-node-01"


# --- F3 (MEC-167): every graphstore.py SQL builder must actually run against
# the migrated ssdf_public view (no "Code 47: unknown column"), the failure
# mode that made locate/neighbors/find_path/topology_snapshot non-functional
# on the public tier after M16a dropped name/identifiers/attrs from the view.


def test_graphstore_builders_run_against_the_public_view(public_client):
    from ssdf_mcp_query.graphstore import (
        build_node_match_sql,
        build_nodes_by_attr_sql,
        build_nodes_by_id_sql,
        build_subgraph_sql,
    )

    node_id = public_client.query(
        "SELECT DISTINCT node_id FROM ssdf_public.graph_nodes WHERE tenant_id = 't_contract_views'"
    ).result_rows[0][0]

    sql, params = build_node_match_sql(node_id, tenant="t_contract_views", schema="ssdf_public")
    rows = public_client.query(sql, parameters=params).result_rows
    assert len(rows) == 1

    sql, params = build_subgraph_sql(
        "2000-01-01T00:00:00+00:00", tenant="t_contract_views", schema="ssdf_public"
    )
    public_client.query(sql, parameters=params)  # must not raise Code 47

    sql, params = build_nodes_by_id_sql([node_id], tenant="t_contract_views", schema="ssdf_public")
    rows = public_client.query(sql, parameters=params).result_rows
    assert len(rows) == 1

    sql, params = build_nodes_by_attr_sql(
        role=None, kind="device", tenant="t_contract_views", schema="ssdf_public"
    )
    public_client.query(sql, parameters=params)  # must not raise Code 47


def test_graphstore_role_filter_refuses_the_public_schema():
    """attrs['role'] is not selectable on the public view -- this must fail
    closed in Python before it ever reaches ClickHouse."""
    from ssdf_mcp_query.graphstore import build_nodes_by_attr_sql

    with pytest.raises(ValueError):
        build_nodes_by_attr_sql(
            role="firewall", kind=None, tenant="t_contract_views", schema="ssdf_public"
        )
