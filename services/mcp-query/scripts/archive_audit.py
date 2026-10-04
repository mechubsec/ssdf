#!/usr/bin/env python3
"""Archive ssdf.audit rows into the retention-safe ssdf.audit_evidence tier (MEC-565).

I/O shell around `ssdf_mcp_query.evidence_archive.rows_due_for_archiving`
(pure decision logic, unit-tested on its own): reads rows from `ssdf.audit`
older than the archive threshold plus the set of row_hash values already
present in `ssdf.audit_evidence`, as the `ssdf_archiver` identity
(023_audit_evidence.sql), asks the pure function which rows are still due,
and inserts them verbatim (same column shape, hash-chain fields included) so
an archived row still verifies against the row_hash it had in `ssdf.audit`.

Idempotent by design: re-running after a partial failure only re-inserts rows
not already found in `ssdf.audit_evidence` (by row_hash) -- see
`rows_due_for_archiving`'s docstring for the legacy-row caveat (empty
row_hash is never treated as "already archived").

Run periodically (e.g. daily), well ahead of `ssdf.audit`'s 90-day TTL
(DEFAULT_ARCHIVE_AFTER_DAYS leaves ten days of margin against a missed run).

Usage (from services/mcp-query, where the package is installed):
    export CH_HOST=... CH_ARCHIVER_PASSWORD=...
    uv run python scripts/archive_audit.py [--archive-after-days 75]
"""

from __future__ import annotations

import argparse
import datetime as dt
import os
import sys

from ssdf_common.config import ConfigError, require_tls_or_loopback
from ssdf_mcp_query.evidence_archive import (
    DEFAULT_ARCHIVE_AFTER_DAYS,
    legacy_content_key,
    rows_due_for_archiving,
)

# How far past the archive cutoff an already-archived row could plausibly be
# and still be a duplicate candidate for the *current* run's cutoff drifting
# day to day. 30 days comfortably covers a missed-run backlog without
# pulling all 410 days of ssdf.audit_evidence on every invocation.
_ALREADY_ARCHIVED_LOOKBACK_DAYS = 30

_AUDIT_COLUMNS = [
    "ts",
    "principal",
    "tier",
    "tool",
    "args",
    "data_classes",
    "decision",
    "row_count",
    "error",
    "client_name",
    "model_id",
    "actor_type",
    "prev_hash",
    "row_hash",
]


def fetch_candidate_rows(client, cutoff: dt.datetime) -> list[dict]:
    """Rows old enough to be worth considering for archiving.

    Filters by ``ts <= cutoff`` in SQL purely to limit how much of
    `ssdf.audit` is pulled across the wire; the exact due/not-due and
    already-archived decisions still belong to `rows_due_for_archiving`.
    """
    res = client.query(
        f"SELECT {', '.join(_AUDIT_COLUMNS)} FROM ssdf.audit WHERE ts <= {{cutoff:DateTime64(3)}}",
        parameters={"cutoff": cutoff},
    )
    rows = [dict(zip(_AUDIT_COLUMNS, row)) for row in res.result_rows]
    # clickhouse-connect returns a DateTime64(_, 'UTC') value as a NAIVE
    # datetime (the column's own timezone already pins its meaning). Attaching
    # UTC explicitly here, before this value is ever written anywhere else,
    # heads off a real bug confirmed by a live run: handing that naive value
    # straight to a later `client.insert(...)` makes clickhouse-connect
    # reinterpret it as wall-clock time in *this process's* local timezone and
    # convert accordingly, silently shifting `ts` by the host's UTC offset on
    # any machine not already running in UTC -- a correctness bug in archived
    # audit timestamps, not merely a display quirk.
    for row in rows:
        if row["ts"].tzinfo is None:
            row["ts"] = row["ts"].replace(tzinfo=dt.timezone.utc)
    return rows


def fetch_already_archived(client, cutoff: dt.datetime) -> tuple[frozenset[str], frozenset[tuple]]:
    """What ``ssdf.audit_evidence`` already holds near the archive boundary.

    Returns ``(row_hash values, legacy content keys)`` -- see
    `evidence_archive.legacy_content_key` for why legacy (pre-chain) rows
    need a different key. Bounded to the last
    ``_ALREADY_ARCHIVED_LOOKBACK_DAYS`` days behind ``cutoff``: a candidate
    row can only ever match something archived at or after its own ``ts``,
    which is itself at or before ``cutoff`` (see `fetch_candidate_rows`), so
    anything archived long before that window is never a duplicate of a
    current candidate and is not worth pulling across the wire.
    """
    bound = cutoff - dt.timedelta(days=_ALREADY_ARCHIVED_LOOKBACK_DAYS)
    res = client.query(
        "SELECT row_hash, ts, principal, tool, args FROM ssdf.audit_evidence "
        "WHERE ts >= {bound:DateTime64(3)}",
        parameters={"bound": bound},
    )
    hashes: set[str] = set()
    legacy_keys: set[tuple] = set()
    for row_hash, ts, principal, tool, args in res.result_rows:
        if row_hash:
            hashes.add(row_hash)
        else:
            legacy_keys.add(
                legacy_content_key({"ts": ts, "principal": principal, "tool": tool, "args": args})
            )
    return frozenset(hashes), frozenset(legacy_keys)


def insert_evidence_rows(client, rows: list[dict]) -> None:
    client.insert(
        "ssdf.audit_evidence",
        [[row[c] for c in _AUDIT_COLUMNS] for row in rows],
        column_names=_AUDIT_COLUMNS,
    )


def run(
    client,
    archive_after_days: int = DEFAULT_ARCHIVE_AFTER_DAYS,
    now: dt.datetime | None = None,
) -> list[dict]:
    """Archive every row due for it. Returns the rows that were inserted.

    Fails closed on any ClickHouse error: a read or insert failure raises
    rather than letting the caller log a wrong "0 archived" success, matching
    scripts/checkpoint_audit.py's own stance on its ClickHouse calls.
    """
    now = now or dt.datetime.now(dt.timezone.utc)
    cutoff = now - dt.timedelta(days=archive_after_days)
    try:
        candidates = fetch_candidate_rows(client, cutoff)
        already_archived, already_archived_legacy_keys = fetch_already_archived(client, cutoff)
        due = rows_due_for_archiving(
            candidates,
            now,
            archive_after_days=archive_after_days,
            already_archived=already_archived,
            already_archived_legacy_keys=already_archived_legacy_keys,
        )
        if due:
            insert_evidence_rows(client, due)
    except Exception as exc:  # noqa: BLE001 -- fail closed on any backend error
        raise RuntimeError(f"archiving failed: {exc}") from exc
    return due


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--archive-after-days",
        type=int,
        default=int(os.environ.get("ARCHIVE_AFTER_DAYS", str(DEFAULT_ARCHIVE_AFTER_DAYS))),
    )
    args = parser.parse_args()

    password = os.environ.get("CH_ARCHIVER_PASSWORD")
    if not password:
        print("CH_ARCHIVER_PASSWORD is required", file=sys.stderr)
        return 2

    host = os.environ.get("CH_HOST", "127.0.0.1")
    secure = os.environ.get("CH_SECURE", "").strip().lower() in ("1", "true")
    try:
        require_tls_or_loopback(host, secure)
    except ConfigError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    import clickhouse_connect

    kwargs: dict = {}
    if secure:
        kwargs["interface"] = "https"
        ca_file = os.environ.get("CH_CA_FILE")
        if ca_file:
            kwargs["ca_cert"] = ca_file

    client = clickhouse_connect.get_client(
        host=host,
        port=int(os.environ.get("CH_PORT", "8123")),
        username="ssdf_archiver",
        password=password,
        database="ssdf",
        **kwargs,
    )

    try:
        archived = run(client, archive_after_days=args.archive_after_days)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f"archived {len(archived)} row(s) into ssdf.audit_evidence")
    return 0


if __name__ == "__main__":
    sys.exit(main())
