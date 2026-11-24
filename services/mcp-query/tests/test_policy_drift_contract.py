"""ssdf#104: live-ClickHouse proof that ssdf.policy_drift collapses a retried
block that carries the same insert_deduplication_token, and that the stored
rows read back with the vector row_hash values."""

from __future__ import annotations

import datetime as dt
import importlib.util
import json
import os
import pathlib
import uuid

import pytest

pytestmark = pytest.mark.contract

clickhouse_connect = pytest.importorskip("clickhouse_connect")

from ssdf_mcp_query.drift_chain import dedup_token  # noqa: E402
from ssdf_mcp_query.verify_drift import _COLUMNS, verify_chains  # noqa: E402

# The contract's head/count SQL lives in the stdlib-only script (single source of truth).
_SPEC = importlib.util.spec_from_file_location(
    "verify_drift_contract",
    pathlib.Path(__file__).resolve().parents[3] / "scripts" / "verify_drift_contract.py",
)
script = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(script)

_VECTORS = json.loads(
    (pathlib.Path(__file__).parent / "fixtures" / "drift_chain_vectors.json").read_text()
)


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


def _table_row(vector: dict) -> list:
    row = dict(vector["row"])
    row["ts"] = dt.datetime.fromisoformat(row["ts"].replace("Z", "+00:00"))
    row["prev_hash"] = vector["prev_hash"]
    row["row_hash"] = vector["row_hash"]
    return [row[c] for c in _COLUMNS]


def test_retried_block_with_same_token_collapses_and_reads_back(raw):
    server_ids = {v["row"]["server_id"] for v in _VECTORS}
    assert len(server_ids) == 1
    server_id = server_ids.pop()
    block = [_table_row(v) for v in _VECTORS[:2]]
    # Unique per invocation: ALTER ... DELETE leaves MergeTree's dedup log intact, so a
    # fixed token makes a rerun against a long-lived ClickHouse insert nothing.
    token = dedup_token(server_id, uuid.uuid4().hex, 1)
    where = {"server_id": server_id}

    raw.command(
        "ALTER TABLE ssdf.policy_drift DELETE WHERE server_id = {server_id:String}",
        parameters=where,
        settings={"mutations_sync": 2},
    )
    try:
        for _ in range(2):  # the second pass is the retry
            raw.insert(
                "ssdf.policy_drift",
                block,
                column_names=_COLUMNS,
                settings={"insert_deduplication_token": token},
            )
        count = raw.query(
            "SELECT count() FROM ssdf.policy_drift WHERE server_id = {server_id:String}",
            parameters=where,
        ).result_rows[0][0]
        assert count == 2

        stored = raw.query(
            "SELECT row_hash FROM ssdf.policy_drift WHERE server_id = {server_id:String} ORDER BY ts",
            parameters=where,
        ).result_rows
        assert [r[0] for r in stored] == [v["row_hash"] for v in _VECTORS[:2]]

        # types must round-trip into compute_row_hash (ts, Array, UInt8)
        result = raw.query(
            f"SELECT {', '.join(_COLUMNS)} FROM ssdf.policy_drift "
            "WHERE server_id = {server_id:String}",
            parameters=where,
        )
        rows = [dict(zip(_COLUMNS, values)) for values in result.result_rows]
        verdict = verify_chains(rows)
        assert verdict["ok"], verdict["issues"]
        assert verdict["chains"][server_id]["anchored"] is True
    finally:
        raw.command(
            "ALTER TABLE ssdf.policy_drift DELETE WHERE server_id = {server_id:String}",
            parameters=where,
            settings={"mutations_sync": 2},
        )


def test_build_drift_sql_runs_against_real_clickhouse(raw):
    """Fakes do not validate SQL: run the builder's query over two inserted rows."""
    from ssdf_mcp_query.drift_tools import DriftTools

    server_id = _VECTORS[0]["row"]["server_id"]
    where = {"server_id": server_id}
    raw.command(
        "ALTER TABLE ssdf.policy_drift DELETE WHERE server_id = {server_id:String}",
        parameters=where,
        settings={"mutations_sync": 2},
    )
    try:
        now = dt.datetime.now(dt.timezone.utc)
        rows = []
        for vector in _VECTORS[:2]:
            row = _table_row(vector)
            row[0] = now  # inside the since_hours window
            rows.append(row)
        raw.insert("ssdf.policy_drift", rows, column_names=_COLUMNS)

        tools = DriftTools(lambda: raw, {"max_execution_time": 10})
        wanted = _VECTORS[0]["row"]["flow_or_isolation_id"]
        everything = tools.policy_drift(device=_VECTORS[0]["row"]["device"], limit=1)
        assert everything["truncated"] is True and everything["row_count"] == 1
        filtered = tools.policy_drift(flow_or_isolation_id=wanted, since_hours=1)
        assert filtered["rows"] and all(
            r["flow_or_isolation_id"] == wanted for r in filtered["rows"]
        )
        assert filtered["rows"][0]["ts"].endswith("Z")
        assert isinstance(filtered["rows"][0]["labmode"], bool)
    finally:
        raw.command(
            "ALTER TABLE ssdf.policy_drift DELETE WHERE server_id = {server_id:String}",
            parameters=where,
            settings={"mutations_sync": 2},
        )


def _seed_and_read(raw, edges, *, duplicate_tail=False):
    """Insert rows ``(row_hash, prev_hash)`` (ts ascending) under a fresh server_id, then
    run the contract's count and head SQL. Returns ``(count, heads, server_id)``."""
    server_id = f"head-{uuid.uuid4().hex}.example.com"
    where = {"sid": server_id}
    base = dt.datetime(2026, 11, 24, 10, 0, tzinfo=dt.timezone.utc)
    rows = [
        [base + dt.timedelta(seconds=i), server_id, "0123abc", "flow-1", "consistent",
         "fw1.example.com", [], "ev/1", 0, prev, row_hash]
        for i, (row_hash, prev) in enumerate(edges)
    ]  # fmt: skip
    try:
        # distinct tokens: identical blocks would otherwise be dropped by block-hash dedup
        for block in rows + (rows[-1:] if duplicate_tail else []):
            raw.insert(
                "ssdf.policy_drift",
                [block],
                column_names=_COLUMNS,
                settings={"insert_deduplication_token": uuid.uuid4().hex},
            )
        count = raw.query(script.COUNT_SQL, parameters=where).result_rows[0][0]
        heads = [  # the driver hands back naive UTC datetimes; the contract's ts is UTC
            (h, t.replace(tzinfo=dt.timezone.utc))
            for h, t in raw.query(script.HEAD_SQL, parameters=where).result_rows
        ]
        return count, heads, rows
    finally:
        raw.command(
            "ALTER TABLE ssdf.policy_drift DELETE WHERE server_id = {sid:String}",
            parameters=where,
            settings={"mutations_sync": 2},
        )


def test_head_sql_empty_chain_is_genesis(raw):
    count, heads, _ = _seed_and_read(raw, [])
    assert (count, heads) == (0, [])
    assert script.resolve_head(count, heads) == ("", None)


def test_head_sql_single_chain_returns_tail_hash_and_ts(raw):
    count, heads, rows = _seed_and_read(raw, [("h1", ""), ("h2", "h1"), ("h3", "h2")])
    assert count == 3
    assert [(h, t) for h, t in heads] == [("h3", rows[2][0])]
    assert script.resolve_head(count, heads) == ("h3", rows[2][0])


def test_head_sql_duplicated_tail_is_one_head(raw):
    count, heads, rows = _seed_and_read(raw, [("h1", ""), ("h2", "h1")], duplicate_tail=True)
    assert count == 3  # the tail really is stored twice
    assert heads == [("h2", rows[1][0])]  # DISTINCT collapses it
    assert script.resolve_head(count, heads) == ("h2", rows[1][0])


def test_head_sql_fork_gives_two_distinct_heads(raw):
    count, heads, _ = _seed_and_read(raw, [("h1", ""), ("ha", "h1"), ("hb", "h1")])
    assert {h for h, _ in heads} == {"ha", "hb"}
    with pytest.raises(SystemExit):
        script.resolve_head(count, heads)


def test_head_sql_rootless_cycle_has_rows_but_no_head(raw):
    count, heads, _ = _seed_and_read(raw, [("ha", "hb"), ("hb", "ha")])
    assert (count, heads) == (2, [])
    with pytest.raises(SystemExit):
        script.resolve_head(count, heads)
