#!/usr/bin/env python3
"""Round-trip verification for the policy-drift contract v1 (ssdf.policy_drift).

**THIS WRITES TO THE TABLE IT VERIFIES.** It appends one drift row (chain
``server_id`` = ``verify-script.example.com``) to whatever ClickHouse it is
pointed at. Use a scratch instance only: it REFUSES any non-loopback host.
Nothing here can delete the row; the scratch server is thrown away instead.

Steps (docs/policy-drift-contract-v1.md, "Seeding protocol"):

1. read the chain head as the verifier identity (``ssdf_audit_verify``)
2. insert one row continuing that head, as the writer identity (``ssdf_drift``)
3. replay the same row: the protocol re-reads the head, sees it landed, skips
4. insert a differing block under the same dedup token, bypassing the head read
   (the unknown-outcome retry); the database must drop it
5. read back, assert exactly one new row, and verify the chain inline

Stdlib only (HTTP interface), so it carries its own copies of ``ts_ms_iso``,
``canonical``, ``compute_row_hash`` and ``dedup_token``; the pin test
``services/mcp-query/tests/test_verify_drift_contract_script.py`` holds them to
``tests/fixtures/drift_chain_vectors.json`` and to the package.

Environment: CH_HOST (default 127.0.0.1), CH_PORT (8123), and optionally
CH_DRIFT_USER/CH_DRIFT_PASSWORD and CH_AUDIT_VERIFY_USER/CH_AUDIT_VERIFY_PASSWORD
(a throwaway server has only ``default`` with no password, which is the default).
"""

import base64
import datetime as dt
import hashlib
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid

LOOPBACK = {"127.0.0.1", "localhost"}  # no ::1: the URL below would need brackets
VERDICTS = frozenset({"consistent", "violating", "over_permissive", "unverifiable"})
SERVER_ID = "verify-script.example.com"
COLUMNS = [
    "ts",
    "server_id",
    "intent_commit",
    "flow_or_isolation_id",
    "verdict",
    "device",
    "device_rule_ids",
    "evidence_ref",
    "labmode",
    "prev_hash",
    "row_hash",
]


def ts_ms_iso(ts: dt.datetime) -> str:
    """UTC ISO-8601 truncated to milliseconds; naive datetimes are assumed UTC."""
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=dt.timezone.utc)
    ts = ts.astimezone(dt.timezone.utc)
    return ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z"


def canonical(row: dict) -> str:
    """Deterministic serialization of a drift row's non-hash fields, in fixed order."""
    if row["verdict"] not in VERDICTS:
        raise ValueError(f"unknown drift verdict: {row['verdict']!r}")
    return json.dumps(
        [
            ts_ms_iso(row["ts"]),
            row["server_id"],
            row["intent_commit"],
            row["flow_or_isolation_id"],
            row["verdict"],
            row["device"],
            list(row["device_rule_ids"]),
            row["evidence_ref"],
            int(row["labmode"]),
        ],
        separators=(",", ":"),
        ensure_ascii=False,
    )


def compute_row_hash(prev_hash: str, row: dict) -> str:
    """row_hash = SHA-256( prev_hash + LF + canonical(row) ), lowercase hex."""
    return hashlib.sha256((prev_hash + "\n" + canonical(row)).encode("utf-8")).hexdigest()


def dedup_token(server_id: str, run_id: str, segment_seq: int) -> str:
    """Length-prefixed, UTF-8 *byte* lengths: injective, and equal to the Rust sink's."""
    return (
        f"{len(server_id.encode('utf-8'))}:{server_id}:"
        f"{len(run_id.encode('utf-8'))}:{run_id}:{segment_seq}"
    )


# The contract's head read (docs/policy-drift-contract-v1.md, "The head read"): the same
# text the contract test runs against real ClickHouse. The server id is a bound parameter.
HEAD_SQL = (
    "SELECT DISTINCT row_hash, ts FROM ssdf.policy_drift WHERE server_id = {sid:String} "
    "AND row_hash NOT IN (SELECT prev_hash FROM ssdf.policy_drift "
    "WHERE server_id = {sid:String})"
)


COUNT_SQL = "SELECT count() FROM ssdf.policy_drift WHERE server_id = {sid:String}"


def resolve_head(count, heads):
    """Contract rule: zero rows is genesis; rows but no head is corruption; one head continues.

    ``heads`` is a list of ``(row_hash, ts)``; returns ``(row_hash, ts)`` or ``("", None)``.
    """
    if count == 0:
        return ("", None)
    distinct = sorted(set(heads))
    if not distinct:
        sys.exit(f"FAIL: {count} rows but no chain head (rootless cycle), refusing to add a root")
    if len(distinct) > 1:
        sys.exit(f"FAIL: {len(distinct)} distinct chain heads (forked chain), refusing to pick one")
    return distinct[0]


def next_ts(now, head_ts):
    """Contract rule: ts must not decrease, so a clock behind the head clamps to head.ts."""
    return now if head_ts is None else max(now, head_ts)


def require_loopback(host: str) -> None:
    """Exit unless host is loopback: this script writes."""
    if host not in LOOPBACK:
        sys.exit(f"refusing non-loopback host {host!r}: this script writes to ssdf.policy_drift")


def ch(host, port, user, password, sql, *, body=None, settings=None):
    """Run one statement over the HTTP interface; ``body`` is a JSONEachRow payload."""
    params = {**(settings or {})}
    data = sql.encode("utf-8")
    if body is not None:
        params["query"] = sql
        data = body.encode("utf-8")
    url = f"http://{host}:{port}/?{urllib.parse.urlencode(params)}"
    request = urllib.request.Request(url, data=data, method="POST")
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    request.add_header("Authorization", f"Basic {token}")
    try:
        return urllib.request.urlopen(request, timeout=30).read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        sys.exit(f"ClickHouse refused: {exc.read().decode('utf-8', 'replace').strip()}")


def read_rows(query):
    """Run a SELECT ... FORMAT JSONEachRow and return rows with ts parsed to datetime."""
    rows = [json.loads(line) for line in query().splitlines() if line]
    for row in rows:
        row["ts"] = dt.datetime.strptime(row["ts"], "%Y-%m-%d %H:%M:%S.%f").replace(
            tzinfo=dt.timezone.utc
        )
    return rows


def verify_chain(rows):
    """Per-server_id check, structural like verify_drift.py: root and head come from links, not ts.

    Returns (summary, problems). An unknown prev_hash is tolerated only on the root
    (genesis aged out, ``anchored`` false); anywhere else it is missing_predecessor.
    """
    problems = []
    own_hashes = {row["row_hash"] for row in rows}
    pointed_at = {row["prev_hash"] for row in rows}
    roots = [r for r in rows if r["prev_hash"] == "" or r["prev_hash"] not in own_hashes]
    # a real genesis wins, then (ts, row_hash); a cycle has no root, so fall back to all rows
    root = min(
        roots or rows, key=lambda r: (r["prev_hash"] != "", r["ts"], r["row_hash"]), default=None
    )
    tips = [r for r in rows if r["row_hash"] not in pointed_at] or rows
    head = max(tips, key=lambda r: (r["ts"], r["row_hash"]), default=None)

    children = {}
    for row in rows:
        children.setdefault(row["prev_hash"], set()).add(row["row_hash"])
        if row["verdict"] not in VERDICTS:
            problems.append(("invalid_verdict", row["row_hash"]))
        elif compute_row_hash(row["prev_hash"], row) != row["row_hash"]:
            problems.append(("content_edit", row["row_hash"]))
        if row["prev_hash"] and row["prev_hash"] not in own_hashes and row is not root:
            problems.append(("missing_predecessor", row["row_hash"]))
    for siblings in children.values():
        if len(siblings) > 1:
            problems.extend(("fork", h) for h in sorted(siblings))
    if len(own_hashes) != len(rows):
        problems.append(("duplicate_row", ""))
    summary = {
        "rows": len(rows),
        "head": head["row_hash"] if head else "",
        "anchored": root is not None and root["prev_hash"] == "",
    }
    return summary, problems


def main() -> int:
    host = os.getenv("CH_HOST", "127.0.0.1")
    port = int(os.getenv("CH_PORT", "8123"))
    require_loopback(host)
    writer = (os.getenv("CH_DRIFT_USER", "default"), os.getenv("CH_DRIFT_PASSWORD", ""))
    reader = (
        os.getenv("CH_AUDIT_VERIFY_USER", "default"),
        os.getenv("CH_AUDIT_VERIFY_PASSWORD", ""),
    )

    def read_head():
        settings = {"param_sid": SERVER_ID}
        count = int(ch(host, port, *reader, COUNT_SQL + " FORMAT TSVRaw", settings=settings))
        out = ch(host, port, *reader, HEAD_SQL + " FORMAT TSVRaw", settings=settings)
        # a TSV line is "<hash>\t<YYYY-MM-DD HH:MM:SS.mmm>"
        heads = [line.split("\t") for line in out.splitlines() if line]
        return resolve_head(
            count,
            [
                (h, dt.datetime.strptime(t, "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=dt.timezone.utc))
                for h, t in heads
            ],
        )

    def insert(row, settings):
        line = {
            k: (row[k].strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] if k == "ts" else row[k])
            for k in COLUMNS
        }
        ch(
            host,
            port,
            *writer,
            "INSERT INTO ssdf.policy_drift FORMAT JSONEachRow",
            body=json.dumps(line),
            settings=settings,
        )

    run_id = "verify-" + uuid.uuid4().hex  # unique per run: a repeated token drops the insert
    token = {"insert_deduplication_token": dedup_token(SERVER_ID, run_id, 0)}

    print("[1/5] reading chain head as the verifier identity")
    head, head_ts = read_head()
    print(f"  head = {head!r} ts={head_ts} (empty means start at genesis)")

    row = {
        "ts": next_ts(dt.datetime.now(dt.timezone.utc).replace(microsecond=123000), head_ts),
        "server_id": SERVER_ID,
        "intent_commit": "0123abc",
        "flow_or_isolation_id": 'flow "1"\n',  # quote and newline are part of the contract
        "verdict": "consistent",
        "device": "fw1.example.com",
        "device_rule_ids": ["r1", "r2"],
        "evidence_ref": "ev/flow-1",
        "labmode": 1,
        "prev_hash": head,
    }
    row["row_hash"] = compute_row_hash(head, row)

    print("[2/5] inserting one row as the writer identity")
    insert(row, token)

    print("[3/5] re-reading the head: it must now be the inserted row, so a replay would skip")
    if read_head()[0] != row["row_hash"]:
        sys.exit("FAIL: the head did not advance to the inserted row")

    print("[4/5] re-inserting a differing block under the same dedup token")
    insert({**row, "evidence_ref": "token-probe"}, token)

    print("[5/5] reading back and verifying inline")
    rows = read_rows(
        lambda: ch(
            host,
            port,
            *reader,
            f"SELECT {', '.join(COLUMNS)} FROM ssdf.policy_drift WHERE server_id = "
            f"'{SERVER_ID}' ORDER BY ts, row_hash FORMAT JSONEachRow",
        )
    )
    landed = [r for r in rows if r["row_hash"] == row["row_hash"]]
    if len(landed) != 1:
        sys.exit(f"FAIL: expected exactly 1 row for the new hash, found {len(landed)}")
    summary, problems = verify_chain(rows)
    if problems:
        sys.exit(f"FAIL: chain issues {problems}")
    print(
        f"PASS drift round-trip: server={SERVER_ID} rows={summary['rows']} "
        f"head={summary['head'][:16]} anchored={str(summary['anchored']).lower()} "
        "replay skipped, tokened duplicate dropped, 0 issues"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
