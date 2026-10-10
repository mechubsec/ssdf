"""Live-ClickHouse proof that TTL expiry actually triggers the failure mode
MEC-559 flagged as unconfirmed by a live run, and that a signed checkpoint
(MEC-565) closes it.

Unlike test_verify_audit.py's checkpoint tests (which simulate an expired
genesis by omitting rows from a Python list) or test_checkpoint_verify.py
(pure signature math), this test proves two things no unit test can: that
ClickHouse's own TTL clause really deletes the earliest row(s) of a live
chain once they age out, and that ``verify_tier`` -- fed exactly what
ClickHouse has left -- reports ``unreachable`` without a checkpoint and clean
with one, against a table whose rows were deleted by real MergeTree TTL
mechanics, not by test code.

A short (2-second) TTL stands in for production's 90-day one: TTL is
evaluated at merge time regardless of the interval's length, so forcing a
merge (``OPTIMIZE ... FINAL``) once the interval has elapsed exercises the
same code path ClickHouse runs on its own schedule against the real table.
Uses a throwaway table, not ``ssdf.audit`` itself, so this has nothing to do
with the real 90-day schema.
"""

from __future__ import annotations

import base64
import datetime as dt
import os
import time

import pytest

pytestmark = pytest.mark.contract

clickhouse_connect = pytest.importorskip("clickhouse_connect")
pytest.importorskip("cryptography")

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from ssdf_mcp_query.audit_chain import compute_row_hash  # noqa: E402
from ssdf_mcp_query.checkpoint_verify import (  # noqa: E402
    Checkpoint,
    canonical_digest,
    key_fingerprint,
)
from ssdf_mcp_query.verify_audit import verify_tier  # noqa: E402

_TABLE = "ssdf.audit_ttl_contract"
_COLUMNS = [
    "ts",
    "principal",
    "tier",
    "tool",
    "args",
    "data_classes",
    "decision",
    "row_count",
    "error",
    "prev_hash",
    "row_hash",
]


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


@pytest.fixture(scope="module", autouse=True)
def table(raw):
    raw.command(f"DROP TABLE IF EXISTS {_TABLE}")
    raw.command(
        f"""
        CREATE TABLE {_TABLE}
        (
            ts           DateTime64(3, 'UTC'),
            principal    LowCardinality(String),
            tier         LowCardinality(String),
            tool         LowCardinality(String),
            args         String,
            data_classes Array(LowCardinality(String)),
            decision     LowCardinality(String),
            row_count    UInt32,
            error        String,
            prev_hash    String DEFAULT '',
            row_hash     String DEFAULT ''
        )
        ENGINE = MergeTree
        ORDER BY (ts, principal)
        TTL toDateTime(ts) + INTERVAL 2 SECOND
        """
    )
    yield
    raw.command(f"DROP TABLE IF EXISTS {_TABLE}")


def _row(i: int, ts: dt.datetime, prev_hash: str) -> dict:
    row = dict(
        ts=ts,
        principal="agent",
        tier="sovereign",
        tool=f"t{i}",
        args="{}",
        data_classes=["topology"],
        decision="allow",
        row_count=i,
        error="",
        prev_hash=prev_hash,
    )
    row["row_hash"] = compute_row_hash(prev_hash, row)
    return row


def _insert(raw, rows: list[dict]) -> None:
    raw.insert(_TABLE, [[row[c] for c in _COLUMNS] for row in rows], column_names=_COLUMNS)


def _sign(checkpoint: Checkpoint, signing_key: Ed25519PrivateKey) -> Checkpoint:
    signature = base64.b64encode(signing_key.sign(canonical_digest(checkpoint))).decode()
    return Checkpoint(**{**checkpoint.__dict__, "signature": signature})


def _format_checkpoint_ts(ts: dt.datetime) -> str:
    """Millisecond-precision RFC3339 with a literal 'Z', matching the shape
    ``_parse_checkpoint_ts`` in verify_audit.py expects."""
    return ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z"


def test_ttl_expiry_closes_without_a_checkpoint_but_opens_with_one(raw):
    now = dt.datetime.now(dt.timezone.utc)
    # The first two rows are timestamped already past the 2-second TTL so they
    # are eligible for eviction as soon as a merge runs; the last two are
    # fresh and must survive untouched.
    expired_ts = now - dt.timedelta(seconds=10)
    fresh_ts = now

    rows: list[dict] = []
    prev = ""
    for i, ts in enumerate([expired_ts, expired_ts + dt.timedelta(milliseconds=1)]):
        rows.append(_row(i, ts, prev))
        prev = rows[-1]["row_hash"]
    for i, ts in enumerate([fresh_ts, fresh_ts + dt.timedelta(milliseconds=1)], start=len(rows)):
        rows.append(_row(i, ts, prev))
        prev = rows[-1]["row_hash"]

    _insert(raw, rows)

    # Force TTL eviction now, rather than waiting for ClickHouse's own
    # schedule: `OPTIMIZE ... FINAL` runs the identical merge-time TTL
    # enforcement a background merge would, just on demand. We can't assert
    # a pre-eviction count here: ClickHouse's own background merge pool can
    # race this check and evict the expired rows before we ever query, so
    # the only deterministic state to converge on is the post-eviction one
    # (2 fresh rows survive, the 2 expired ones don't).
    deadline = time.monotonic() + 30
    remaining = raw.query(f"SELECT count() FROM {_TABLE}").result_rows[0][0]
    while remaining != 2:
        raw.command(f"OPTIMIZE TABLE {_TABLE} FINAL")
        remaining = raw.query(f"SELECT count() FROM {_TABLE}").result_rows[0][0]
        if remaining != 2:
            if time.monotonic() > deadline:
                pytest.fail(
                    f"ClickHouse TTL did not converge on 2 surviving rows within 30s (got {remaining})"
                )
            time.sleep(1)

    surviving_raw = raw.query(f"SELECT {', '.join(_COLUMNS)} FROM {_TABLE} ORDER BY ts").result_rows
    surviving = [dict(zip(_COLUMNS, r)) for r in surviving_raw]
    surviving_hashes = {r["row_hash"] for r in surviving}

    # The real assertion this whole test exists for: TTL actually deleted the
    # genesis row, via ClickHouse's own eviction, not a Python-level stand-in.
    assert rows[0]["row_hash"] not in surviving_hashes
    assert rows[1]["row_hash"] not in surviving_hashes
    assert len(surviving) == 2

    # 1. MEC-559's unconfirmed failure mode, now confirmed live: with no
    #    checkpoint, the surviving rows are unreachable from a genesis that
    #    ClickHouse has actually deleted.
    issues_no_checkpoint = verify_tier(surviving)
    assert {i["type"] for i in issues_no_checkpoint} >= {"unreachable"}
    assert len([i for i in issues_no_checkpoint if i["type"] == "unreachable"]) == 2

    # 2. MEC-565's fix: a checkpoint signed (over the full original chain,
    #    before TTL ran) while rows[1] was still the chain head anchors the
    #    surviving rows back in. Dated far in the past so it clears
    #    _is_old_enough_to_anchor's production-scale (90-day) threshold for
    #    a head that has, in this test, already aged out of the table.
    signing_key = Ed25519PrivateKey.generate()
    verifying_key = signing_key.public_key().public_bytes_raw()
    fingerprint = key_fingerprint(verifying_key)
    old_anchor = _sign(
        Checkpoint(
            tier="sovereign",
            server_id="",
            row_count=2,
            head_row_hash=rows[1]["row_hash"],
            checkpoint_ts="2026-01-01T00:00:00.000Z",
            signature="",
            key_id=fingerprint,
        ),
        signing_key,
    )
    # A second, recent checkpoint over the still-live tip (rows[3]) -- without
    # it, old_anchor alone would also be the *latest* verified checkpoint, and
    # being >2 days stale relative to the fresh surviving rows would trip the
    # MEC-1634 stale_checkpoint check that this same old date is required to
    # satisfy above. A real deployment never hits this: checkpoints run on a
    # schedule, so the one anchoring a long-expired head is never also the
    # latest one.
    recent_anchor = _sign(
        Checkpoint(
            tier="sovereign",
            server_id="",
            row_count=4,
            head_row_hash=rows[3]["row_hash"],
            checkpoint_ts=_format_checkpoint_ts(now + dt.timedelta(seconds=1)),
            signature="",
            key_id=fingerprint,
        ),
        signing_key,
    )

    issues_with_checkpoint = verify_tier(
        surviving,
        checkpoints=[old_anchor, recent_anchor],
        keyring={fingerprint: verifying_key},
    )
    assert issues_with_checkpoint == []
