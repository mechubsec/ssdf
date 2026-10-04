"""Pure logic for picking ssdf.audit rows due to be archived (MEC-565).

No I/O. scripts/archive_audit.py owns reading candidate rows from ssdf.audit
and writing them to ssdf.audit_evidence (023_audit_evidence.sql); this module
decides which rows are due.

Archive well before the 90-day TTL (009_audit_hash_chain.sql), not at the
boundary: the archiver runs periodically (e.g. daily), and a row that ages
past 90 days between two runs would be deleted before ever being copied. The
default threshold leaves ten days of margin against a missed or delayed run.
"""

from __future__ import annotations

import datetime as _dt

DEFAULT_ARCHIVE_AFTER_DAYS = 75


def legacy_content_key(row: dict) -> tuple:
    """The dedup key for a legacy (pre-chain) row: its hash chain columns are
    all the empty-string DEFAULT, so ``row_hash`` can never distinguish one
    legacy row from another. ``(ts, principal, tool, args)`` is unique enough
    in practice -- it is exactly what two writers racing to produce an
    identical row would need to collide on, which does not happen."""
    ts = row["ts"]
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=_dt.timezone.utc)
    return (ts, row.get("principal"), row.get("tool"), row.get("args"))


def rows_due_for_archiving(
    rows: list[dict],
    now: _dt.datetime,
    archive_after_days: int = DEFAULT_ARCHIVE_AFTER_DAYS,
    already_archived: frozenset[str] = frozenset(),
    already_archived_legacy_keys: frozenset[tuple] = frozenset(),
) -> list[dict]:
    """Rows old enough to archive and not already copied.

    ``already_archived`` is the set of ``row_hash`` values the destination
    table already holds, read back by the caller before calling this -- this
    is what makes a re-run after a partial failure safe: a row already
    present in ssdf.audit_evidence is skipped rather than inserted again.

    Legacy rows (pre-chain, ``row_hash == ''``) cannot be deduplicated that
    way -- every legacy row shares the same empty sentinel, so matching on it
    would make archiving any one of them hide all the others. Those are
    instead matched by ``already_archived_legacy_keys``
    (:func:`legacy_content_key` applied to rows the destination already
    holds). Without this, a daily run between day ``archive_after_days`` and
    the TTL boundary re-inserts every surviving legacy row on every run.
    """
    if now.tzinfo is None:
        now = now.replace(tzinfo=_dt.timezone.utc)
    cutoff = now - _dt.timedelta(days=archive_after_days)
    due = []
    for row in rows:
        ts = row["ts"]
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=_dt.timezone.utc)
        if ts > cutoff:
            continue
        row_hash = row.get("row_hash", "")
        if row_hash:
            if row_hash in already_archived:
                continue
        elif legacy_content_key(row) in already_archived_legacy_keys:
            continue
        due.append(row)
    return due
