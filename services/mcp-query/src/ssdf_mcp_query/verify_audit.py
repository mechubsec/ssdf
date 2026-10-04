"""Offline tamper-evidence verifier for the ssdf.audit hash chain (M3).

Reads as the read-only ``ssdf_audit_verify`` identity, groups rows by
**(tier, server_id)**, and follows each chain's prev_hash -> row_hash linkage
from genesis (prev_hash == "").

Why per writer rather than per tier: the ``evidence`` tier has fifteen MCP
servers writing it. A single chain per tier would require every writer to
serialise against a shared head, and there is no such lock — so each seeds
``prev_hash=""`` and the tier acquires one accepted root per server. With many
roots, deleting an entire run removes a whole independent root and leaves
nothing unreachable, so the verifier reports clean on missing evidence. Grouped
by writer, each server has exactly one root, and a run that continues its
predecessor makes a wholesale deletion visible as ``missing_predecessor``
(ssdf#47). Rows without a ``server_id`` — every ``sovereign`` row — group by
tier alone and verify exactly as before.
Detects: content edits (recomputed hash != stored), deletions (a prev_hash naming
a missing row), and insertions/reorders (rows unreachable from genesis). Follows
the linkage, NOT ts ordering, so same-millisecond ts ties never false-positive.

Usage: python -m ssdf_mcp_query.verify_audit
Exit code 0 = all tiers clean; 1 = at least one issue (or 2 = config error).
"""

from __future__ import annotations

import datetime as dt
import json
import sys
from collections import defaultdict

from .audit_chain import compute_row_hash
from .checkpoint_verify import (
    Checkpoint,
    CheckpointVerificationError,
    verify_checkpoint_signature,
)
from .config import ch_tls_kwargs, load_config

# ssdf.audit's TTL (007_audit.sql / 009_audit_hash_chain.sql). A checkpoint
# can only legitimately stand in for rows that have actually had time to
# expire -- see _is_old_enough_to_anchor.
_AUDIT_TTL_DAYS = 90

# How much slack to give the checkpoint schedule (nominally daily) against
# _AUDIT_TTL_DAYS: a checkpoint taken up to this many days before the TTL
# boundary is still trusted, so an anchor is not rejected purely because the
# checkpoint job ran a little early relative to the exact expiry instant.
_CHECKPOINT_INTERVAL_SLACK_DAYS = 2

_VERIFY_COLUMNS = [
    "ts",
    "principal",
    "tier",
    "tool",
    "args",
    "data_classes",
    "decision",
    "row_count",
    "error",
    # Attribution (issue #9). MUST be selected: canonical() folds these into the
    # hash when present, so a verifier that ignored them would recompute the
    # nine-field form for an attributed row and report a false mismatch.
    "client_name",
    "model_id",
    "actor_type",
    "prev_hash",
    "row_hash",
]


def group_key(row: dict) -> tuple[str, str]:
    """The chain a row belongs to: its tier, and its writer when it names one.

    ``server_id`` lives inside the JSON ``args`` payload rather than in a
    column, so this parses defensively: a row whose args are absent, malformed
    or lack the field falls back to tier-only grouping, which is the historical
    behaviour and the right answer for sovereign rows.

    For an **evidence** row that fallback is a defect rather than a default, and
    :func:`writer_issue` reports it — see the note there.
    """
    raw = row.get("args") or ""
    server_id = ""
    if raw:
        try:
            parsed = json.loads(raw)
        except (TypeError, ValueError):
            parsed = None
        if isinstance(parsed, dict):
            value = parsed.get("server_id")
            if isinstance(value, str):
                server_id = value
    return (row["tier"], server_id)


def writer_issue(row: dict) -> dict | None:
    """Report an evidence row that does not name the chain it belongs to.

    Evidence chains are keyed ``(tier, server_id)``. A row whose ``args`` are
    malformed, omit ``server_id``, or carry a non-string or empty one has no
    usable key, and grouping it under the tier alone is not harmless: several
    such rows share that bucket, each contributes its own root, and the whole
    set verifies as clean. That is precisely the deletion blind spot per-writer
    grouping was introduced to close, arrived at from the other direction.

    Only the evidence tier is held to this. Sovereign rows never carried a
    writer — all 20,193 of them predate the field — so requiring one there would
    turn every historical row into an issue over a rule that was never made
    about them.
    """
    if row.get("tier") != "evidence":
        return None
    _, server_id = group_key(row)
    if server_id:
        return None
    return {"type": "unidentified_writer", "row_hash": row.get("row_hash", "")}


def _parse_checkpoint_ts(checkpoint_ts: str) -> dt.datetime:
    """Parse a checkpoint's RFC3339 ``checkpoint_ts`` (millisecond precision,
    literal 'Z' -- the exact shape scripts/checkpoint_audit.py's
    ``format_checkpoint_ts`` produces)."""
    return dt.datetime.strptime(checkpoint_ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
        tzinfo=dt.timezone.utc
    )


def _is_old_enough_to_anchor(checkpoint_ts: str, now: dt.datetime) -> bool:
    """Whether the rows a checkpoint stands in for could actually have
    expired by ``now``.

    A checkpoint taken moments after a recent, not-yet-TTL-expired prefix of
    the chain was removed would otherwise verify just as cleanly as one
    anchoring a genuinely expired genesis, which would make an
    otherwise-detectable early deletion indistinguishable from ordinary TTL
    expiry. A checkpoint is only trusted as an anchor once it is old enough
    that the rows up to its head are past (or almost past) the TTL boundary
    on their own.
    """
    try:
        checkpoint_time = _parse_checkpoint_ts(checkpoint_ts)
    except ValueError:
        return False
    age = now - checkpoint_time
    return age >= dt.timedelta(days=_AUDIT_TTL_DAYS - _CHECKPOINT_INTERVAL_SLACK_DAYS)


def _verify_checkpoint_anchor(
    checkpoint: Checkpoint, verifying_key: bytes | None, now: dt.datetime
) -> dict | None:
    """Whether ``checkpoint`` may be trusted as an anchor: its signature must
    verify against ``verifying_key``, and it must be old enough that the rows
    it stands in for could actually have expired. Returns the issue to report
    when it fails either check, or ``None`` when it passes.
    """
    if verifying_key is None:
        return {"type": "unverifiable_checkpoint", "row_hash": checkpoint.head_row_hash}
    try:
        verify_checkpoint_signature(checkpoint, verifying_key)
    except CheckpointVerificationError:
        return {"type": "unverifiable_checkpoint", "row_hash": checkpoint.head_row_hash}
    if not _is_old_enough_to_anchor(checkpoint.checkpoint_ts, now):
        return {"type": "premature_truncation", "row_hash": checkpoint.head_row_hash}
    return None


def _anchor_dangling_hash(
    prev_hash: str,
    checkpoints_by_head: dict[str, list[Checkpoint]],
    bridge_by_hash: dict[str, dict],
    verifying_key: bytes | None,
    now: dt.datetime,
) -> tuple[bool, list[dict]]:
    """Try to anchor one dangling ``prev_hash``: either directly against a
    checkpoint whose ``head_row_hash`` matches it, or by walking backward
    through evidence-tier rows (``bridge_by_hash``) until reaching one that
    does.

    A checkpoint taken on a fixed schedule does not generally sit at exactly
    the row that has just aged out of ``ssdf.audit`` -- it sits wherever the
    chain tip was when the job last ran, which under a per-row TTL is almost
    always a different row from whichever one expired most recently. The gap
    between the two is bridged through ``ssdf.audit_evidence``
    (023_audit_evidence.sql), which retains rows for far longer than
    ``ssdf.audit``'s TTL. Each bridge row's own content is recomputed and
    checked before its ``prev_hash`` is trusted to continue the walk, so a
    tampered bridge row cannot be used to extend the anchor further back. The
    direct-match case is simply a walk of length zero.

    Bounded by the number of distinct bridge rows available, so a cyclic or
    unresolvable bridge terminates rather than looping forever.
    """
    current = prev_hash
    visited: set[str] = set()
    issues: list[dict] = []
    for _ in range(len(bridge_by_hash) + 1):
        candidates = checkpoints_by_head.get(current)
        if candidates:
            for checkpoint in candidates:
                issue = _verify_checkpoint_anchor(checkpoint, verifying_key, now)
                if issue is None:
                    return True, issues
                issues.append(issue)
            return False, issues
        if current in visited:
            return False, issues
        visited.add(current)
        bridge_row = bridge_by_hash.get(current)
        if bridge_row is None:
            return False, issues
        if compute_row_hash(bridge_row["prev_hash"], bridge_row) != bridge_row["row_hash"]:
            issues.append({"type": "content_edit", "row_hash": bridge_row["row_hash"]})
            return False, issues
        current = bridge_row["prev_hash"]
    return False, issues


def _checkpoint_head_issues(
    checkpoints: list[Checkpoint],
    by_hash: dict[str, dict],
    bridge_by_hash: dict[str, dict],
    verifying_key: bytes | None,
    now: dt.datetime,
) -> list[dict]:
    """Every checkpoint's signature is verified regardless of age; age only
    gates the head-presence check."""
    if verifying_key is None:
        return []
    issues: list[dict] = []
    for checkpoint in checkpoints:
        try:
            verify_checkpoint_signature(checkpoint, verifying_key)
        except CheckpointVerificationError:
            issues.append({"type": "unverifiable_checkpoint", "row_hash": checkpoint.head_row_hash})
            continue
        if _is_old_enough_to_anchor(checkpoint.checkpoint_ts, now):
            continue
        if (
            checkpoint.head_row_hash not in by_hash
            and checkpoint.head_row_hash not in bridge_by_hash
        ):
            issues.append({"type": "checkpoint_head_missing", "row_hash": checkpoint.head_row_hash})
    return issues


def _select_checkpoint_anchors(
    checkpoints: list[Checkpoint],
    verifying_key: bytes | None,
    dangling_prev_hashes: set[str],
    bridge_rows: list[dict],
    now: dt.datetime,
) -> tuple[set[str], list[dict]]:
    """Pick which dangling predecessors can be anchored, either directly
    against a checkpoint or by bridging through evidence-tier rows
    (``_anchor_dangling_hash``).

    Only a dangling ``prev_hash`` is ever considered as a starting point --
    not simply "the most recent checkpoint for this chain". With a regular
    checkpoint schedule, the most recent checkpoint's head sits at or near
    the current chain tip, which is never what an expired genesis's
    successor points to; selecting it anyway would mean every chain reports
    tamper indefinitely once its genesis ages out.

    A checkpoint reached by neither a direct match nor a bridge walk from any
    dangling hash is never even verified: it is irrelevant to this chain's
    reachability and would only add a spurious ``unverifiable_checkpoint``
    issue for a signature nobody needed.
    """
    checkpoints_by_head: dict[str, list[Checkpoint]] = defaultdict(list)
    for checkpoint in checkpoints:
        checkpoints_by_head[checkpoint.head_row_hash].append(checkpoint)
    bridge_by_hash = {r["row_hash"]: r for r in bridge_rows}

    anchors: set[str] = set()
    issues: list[dict] = []
    for prev_hash in dangling_prev_hashes:
        anchored, hash_issues = _anchor_dangling_hash(
            prev_hash, checkpoints_by_head, bridge_by_hash, verifying_key, now
        )
        if anchored:
            anchors.add(prev_hash)
        else:
            issues.extend(hash_issues)
    return anchors, issues


def verify_tier(
    rows: list[dict],
    checkpoints: list[Checkpoint] = (),
    bridge_rows: list[dict] = (),
    verifying_key: bytes | None = None,
    now: dt.datetime | None = None,
) -> list[dict]:
    """Verify one tier's rows. Returns a list of issue dicts (empty == clean).

    Rows written before migration 009 carry prev_hash='' / row_hash='' (column
    DEFAULT) and are excluded: the first hashed row per tier is that tier's
    chain start. A blanked-hash tamper on a chained row is still caught — its
    successor's prev_hash names a now-missing row_hash (missing_predecessor).

    ``checkpoints`` and ``verifying_key`` are only consulted when this
    chain's genesis row is absent from ``rows`` -- i.e. it has expired past
    the 90-day TTL. Callers that never pass them get exactly today's
    behaviour: an expired genesis makes every surviving row ``unreachable``.

    ``bridge_rows`` are this chain's evidence-tier rows (``ssdf.audit_evidence``),
    which outlive ``ssdf.audit``'s TTL by a wide margin. They let a dangling
    predecessor be traced back to a checkpoint that does not sit exactly at
    the row the TTL most recently evicted -- see ``_anchor_dangling_hash``.
    Callers that never pass them get only the direct-match case: a dangling
    hash anchors only when some checkpoint's ``head_row_hash`` matches it
    exactly.

    ``now`` is when "old enough to have expired" is measured from; defaults
    to the real current time. Only matters together with ``checkpoints`` --
    see ``_is_old_enough_to_anchor``.
    """
    now = now or dt.datetime.now(dt.timezone.utc)
    rows = [r for r in rows if r["row_hash"] != ""]
    issues: list[dict] = []
    by_hash = {r["row_hash"]: r for r in rows}
    bridge_by_hash = {r["row_hash"]: r for r in bridge_rows}

    # 0. Duplicates. A retry after an ambiguous INSERT timeout can land the same
    #    row twice: the sink cannot tell whether the timed-out request committed,
    #    its high-water read can answer "nothing landed", and the original then
    #    commits alongside the retry. The pair is invisible to every check below
    #    -- identical content means an identical row_hash, so `by_hash` collapses
    #    them into one entry and linkage and reachability both pass. Counting is
    #    the only thing that sees it.
    seen: dict[str, int] = defaultdict(int)
    for r in rows:
        seen[r["row_hash"]] += 1
    for row_hash, count in seen.items():
        if count > 1:
            issues.append({"type": "duplicate_row", "row_hash": row_hash})

    # 0.5 Forks: two rows naming the same prev_hash (including two genesis
    #     rows, prev_hash == "") split the chain into branches that each still
    #     link and reach correctly on their own -- neither the content-
    #     integrity check below nor reachability (3) sees anything wrong with
    #     either branch, so this has to be checked on its own. Grouped by
    #     distinct row_hash so an exact duplicate (already reported above) is
    #     never also counted as a fork.
    children_by_prev: dict[str, set[str]] = defaultdict(set)
    for r in rows:
        children_by_prev[r["prev_hash"]].add(r["row_hash"])
    for children in children_by_prev.values():
        if len(children) > 1:
            for child_hash in children:
                issues.append({"type": "fork", "row_hash": child_hash})

    # 1. Content integrity: each stored row_hash must equal H(prev_hash, fields).
    for r in rows:
        if compute_row_hash(r["prev_hash"], r) != r["row_hash"]:
            issues.append({"type": "content_edit", "row_hash": r["row_hash"]})

    # 1.5 Checkpoint head presence: every checkpoint still within its recent
    # window must have its head findable, independent of whether this
    # chain's genesis survives -- see _checkpoint_head_issues.
    issues.extend(
        _checkpoint_head_issues(list(checkpoints), by_hash, bridge_by_hash, verifying_key, now)
    )

    # Genesis-or-checkpoint anchor selection, done once up front so both the
    # linkage check (2) and reachability (3) below agree on what counts as a
    # legitimate root. A checkpoint (direct or bridged) is only consulted
    # when this chain's own genesis row (prev_hash == "") is absent -- a
    # chain that still has its genesis needs no anchor and MUST ignore any
    # checkpoint it is handed (stale or even malformed), since consulting one
    # it does not need would let a bad checkpoint affect a chain it has
    # nothing to do with.
    has_genesis = any(r["prev_hash"] == "" for r in rows)
    anchor_hashes: set[str] = set()
    if not has_genesis and rows:
        dangling = {
            r["prev_hash"] for r in rows if r["prev_hash"] != "" and r["prev_hash"] not in by_hash
        }
        anchor_hashes, anchor_issues = _select_checkpoint_anchors(
            list(checkpoints), verifying_key, dangling, list(bridge_rows), now
        )
        issues.extend(anchor_issues)

    # 2. Linkage: a non-genesis prev_hash must name a present row, UNLESS it
    #    is itself a trusted anchor -- a hash that stands in for a row that
    #    once existed but has since expired out of ssdf.audit.
    for r in rows:
        if (
            r["prev_hash"] != ""
            and r["prev_hash"] not in by_hash
            and r["prev_hash"] not in anchor_hashes
        ):
            issues.append({"type": "missing_predecessor", "row_hash": r["row_hash"]})

    # 3. Reachability from genesis (prev_hash == ""), extended by any row
    #    chaining directly from a trusted anchor.
    children: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        children[r["prev_hash"]].append(r)
    reachable: set[str] = set()
    stack = list(children.get("", []))
    for anchor_hash in anchor_hashes:
        stack.extend(children.get(anchor_hash, []))
    while stack:
        r = stack.pop()
        if r["row_hash"] in reachable:
            continue
        reachable.add(r["row_hash"])
        stack.extend(children.get(r["row_hash"], []))
    for r in rows:
        if r["row_hash"] not in reachable:
            issues.append({"type": "unreachable", "row_hash": r["row_hash"]})

    return issues


_CHECKPOINT_COLUMNS = [
    "tier",
    "server_id",
    "row_count",
    "head_row_hash",
    "checkpoint_ts",
    "signature",
    "key_id",
]


def _make_client(config):
    import clickhouse_connect

    return clickhouse_connect.get_client(
        host=config.ch_host,
        port=config.ch_port,
        username="ssdf_audit_verify",
        password=config.ch_audit_verify_password.get(),
        database=config.ch_database,
        **ch_tls_kwargs(config),
    )


def _fetch_rows(config) -> list[dict]:
    client = _make_client(config)
    res = client.query(f"SELECT {', '.join(_VERIFY_COLUMNS)} FROM ssdf.audit ORDER BY ts ASC")
    return [dict(zip(_VERIFY_COLUMNS, row)) for row in res.result_rows]


# How far back to read ssdf.audit_evidence for bridge rows. The walk only
# ever needs to reach from the current TTL boundary to the nearest
# checkpoint, which under a daily schedule is at most a few days -- this
# bound is generous relative to that, so it never limits what a real
# deployment can anchor while keeping the query's result set small.
_EVIDENCE_BRIDGE_LOOKBACK_DAYS = 120


def _fetch_evidence_rows(config, now: dt.datetime) -> dict[tuple[str, str], list[dict]]:
    """This chain's evidence-tier rows available as bridge material, grouped
    the same way as ``_fetch_rows``. Requires ``ssdf_audit_verify`` to hold
    SELECT on ``ssdf.audit_evidence`` (022_audit_checkpoints.sql /
    023_audit_evidence.sql)."""
    since = now - dt.timedelta(days=_EVIDENCE_BRIDGE_LOOKBACK_DAYS)
    client = _make_client(config)
    res = client.query(
        f"SELECT {', '.join(_VERIFY_COLUMNS)} FROM ssdf.audit_evidence "
        "WHERE ts >= {since:DateTime64(3)} ORDER BY ts ASC",
        parameters={"since": since},
    )
    by_chain: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for values in res.result_rows:
        row = dict(zip(_VERIFY_COLUMNS, values))
        by_chain[group_key(row)].append(row)
    return by_chain


def _fetch_checkpoints(config) -> dict[tuple[str, str], list[Checkpoint]]:
    client = _make_client(config)
    res = client.query(
        f"SELECT {', '.join(_CHECKPOINT_COLUMNS)} FROM ssdf.audit_checkpoints "
        "ORDER BY checkpoint_ts ASC"
    )
    by_chain: dict[tuple[str, str], list[Checkpoint]] = defaultdict(list)
    for values in res.result_rows:
        row = dict(zip(_CHECKPOINT_COLUMNS, values))
        checkpoint = Checkpoint(
            tier=row["tier"],
            server_id=row["server_id"],
            row_count=int(row["row_count"]),
            head_row_hash=row["head_row_hash"],
            checkpoint_ts=row["checkpoint_ts"],
            signature=row["signature"],
            key_id=row["key_id"],
        )
        by_chain[(checkpoint.tier, checkpoint.server_id)].append(checkpoint)
    return by_chain


def _load_verifying_key(config) -> bytes | None:
    """Load the checkpoint verifying key, or None when checkpoint-based
    verification is not configured (fail closed to today's behaviour, not to
    an exception, since most deployments will not have rolled this out yet)."""
    if not config.ch_checkpoint_verify_key_path:
        return None
    from .checkpoint_verify import load_verifying_key

    try:
        return load_verifying_key(config.ch_checkpoint_verify_key_path)
    except CheckpointVerificationError as exc:
        print(f"warning: could not load checkpoint verifying key: {exc}", file=sys.stderr)
        return None


def main() -> int:
    config = load_config()
    if not config.ch_audit_verify_password:
        print("CH_AUDIT_VERIFY_PASSWORD is required to verify the audit chain", file=sys.stderr)
        return 2
    rows = _fetch_rows(config)
    checkpoints_by_chain = _fetch_checkpoints(config)
    verifying_key = _load_verifying_key(config)
    now = dt.datetime.now(dt.timezone.utc)
    evidence_by_chain = _fetch_evidence_rows(config, now)
    by_chain: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for r in rows:
        by_chain[group_key(r)].append(r)
    total = 0
    # Iterate every chain that has EITHER surviving rows OR a checkpoint --
    # not just `by_chain`'s keys. A chain whose rows were all removed from
    # ssdf.audit has no entry in `by_chain` at all, and skipping it here
    # would skip verify_tier()'s checkpoint-head check for it too.
    all_chains = set(by_chain) | set(checkpoints_by_chain)
    for tier, server_id in sorted(all_chains):
        chain_rows = by_chain.get((tier, server_id), [])
        issues = verify_tier(
            chain_rows,
            checkpoints=checkpoints_by_chain.get((tier, server_id), []),
            bridge_rows=evidence_by_chain.get((tier, server_id), []),
            verifying_key=verifying_key,
            now=now,
        )
        # An evidence row with no usable writer cannot be chained to anything,
        # so it is reported rather than quietly folded into the tier bucket.
        issues.extend(issue for row in chain_rows if (issue := writer_issue(row)))
        total += len(issues)
        legacy = sum(1 for r in chain_rows if r["row_hash"] == "")
        status = "OK" if not issues else f"{len(issues)} ISSUE(S)"
        writer = f" server={server_id}" if server_id else ""
        print(f"tier={tier}{writer} rows={len(chain_rows)} legacy_unhashed={legacy} {status}")
        for issue in issues:
            print(f"  {issue['type']}: row_hash={issue['row_hash'][:16]}…")
    return 0 if total == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
