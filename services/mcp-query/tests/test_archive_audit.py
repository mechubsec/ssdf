from __future__ import annotations

import datetime as dt
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import archive_audit  # noqa: E402

NOW = dt.datetime(2026, 10, 3, tzinfo=dt.timezone.utc)


class _FakeResult:
    def __init__(self, result_rows):
        self.result_rows = result_rows


class _FakeClient:
    def __init__(self, audit_rows=(), evidence_row_hashes=(), evidence_rows=None):
        self._audit_rows = list(audit_rows)
        if evidence_rows is not None:
            self._evidence_rows = list(evidence_rows)
        else:
            self._evidence_rows = [
                (h, NOW - dt.timedelta(days=80), "agent", "tool", "{}") for h in evidence_row_hashes
            ]
        self.inserted: list[tuple[str, list, list]] = []
        self.queries: list[str] = []

    def query(self, sql, parameters=None):
        self.queries.append(sql)
        if "FROM ssdf.audit_evidence" in sql:
            return _FakeResult(list(self._evidence_rows))
        if "FROM ssdf.audit" in sql:
            return _FakeResult(list(self._audit_rows))
        raise AssertionError(f"unexpected query: {sql}")

    def insert(self, table, data, column_names):
        self.inserted.append((table, data, column_names))


def _audit_row(days_old: int, row_hash: str = "") -> tuple:
    ts = NOW - dt.timedelta(days=days_old)
    return (ts, "agent", "evidence", "tool", "{}", [], "allow", 1, "", "", "", "", "", row_hash)


def test_fetch_already_archived_queries_the_evidence_table():
    client = _FakeClient(evidence_row_hashes=["abc"])
    hashes, legacy_keys = archive_audit.fetch_already_archived(client, NOW)
    assert hashes == frozenset({"abc"})
    assert legacy_keys == frozenset()
    assert "ssdf.audit_evidence" in client.queries[0]


def test_fetch_already_archived_returns_legacy_content_keys():
    """Legacy (pre-chain) rows share the empty row_hash sentinel, so they are
    matched by content (ts, principal, tool, args) instead -- see
    evidence_archive.legacy_content_key. This is what makes a second run not
    re-insert the same legacy row it already copied."""
    ts = NOW - dt.timedelta(days=80)
    client = _FakeClient(evidence_rows=[("", ts, "agent", "tool", "{}")])
    _, legacy_keys = archive_audit.fetch_already_archived(client, NOW)
    assert legacy_keys == {(ts, "agent", "tool", "{}")}


def test_run_archives_old_rows_not_already_copied(monkeypatch):
    old_row = _audit_row(80, row_hash="new-hash")
    already_copied = _audit_row(90, row_hash="old-hash")
    fresh_row = _audit_row(10, row_hash="too-fresh")
    client = _FakeClient(
        audit_rows=[old_row, already_copied, fresh_row],
        evidence_row_hashes=["old-hash"],
    )

    archived = archive_audit.run(client, archive_after_days=75, now=NOW)

    assert len(archived) == 1
    assert archived[0]["row_hash"] == "new-hash"
    assert len(client.inserted) == 1
    table, data, columns = client.inserted[0]
    assert table == "ssdf.audit_evidence"
    assert columns == archive_audit._AUDIT_COLUMNS
    assert data == [[archived[0][c] for c in archive_audit._AUDIT_COLUMNS]]


def test_run_does_not_insert_when_nothing_is_due():
    fresh_row = _audit_row(1, row_hash="fresh")
    client = _FakeClient(audit_rows=[fresh_row])

    archived = archive_audit.run(client, archive_after_days=75, now=NOW)

    assert archived == []
    assert client.inserted == []


def test_fetch_candidate_rows_passes_cutoff_parameter():
    client = _FakeClient(audit_rows=[])
    cutoff = NOW - dt.timedelta(days=75)
    archive_audit.fetch_candidate_rows(client, cutoff)
    assert "ssdf.audit" in client.queries[0]


def test_fetch_candidate_rows_attaches_utc_to_naive_timestamps():
    """Regression test for a live-run-confirmed bug: clickhouse-connect
    returns a DateTime64(_, 'UTC') value as a NAIVE datetime. Handing that
    straight to a later client.insert() makes clickhouse-connect reinterpret
    it as local wall-clock time and shift it by the host's UTC offset --
    reproduced live by round-tripping a DateTime64('UTC') value between two
    tables on a non-UTC host, where it came back four hours later than it
    went in. Attaching tzinfo=UTC here, right after the read, is what stops
    insert_evidence_rows from ever seeing an ambiguous naive value."""
    naive_row = (
        dt.datetime(2026, 7, 1, 12, 0, 0),
        "agent",
        "evidence",
        "tool",
        "{}",
        [],
        "allow",
        1,
        "",
        "",
        "",
        "",
        "",
        "h",
    )
    client = _FakeClient(audit_rows=[naive_row])

    rows = archive_audit.fetch_candidate_rows(client, NOW)

    assert rows[0]["ts"] == dt.datetime(2026, 7, 1, 12, 0, 0, tzinfo=dt.timezone.utc)
    assert rows[0]["ts"].tzinfo is not None
