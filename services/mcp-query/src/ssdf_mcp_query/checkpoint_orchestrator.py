"""Pure logic for computing the next ssdf.audit chain checkpoint (MEC-565).

No I/O. scripts/checkpoint_audit.py owns querying ClickHouse for a chain's
current rows and the previous checkpoint, calling this to decide what the
next checkpoint should say, then shelling out to the Rust
`mecmcp-audit-checkpoint` binary to sign it and inserting the signed result
into ssdf.audit_checkpoints.

Why `row_count` is a running total, not `len(rows)`: `rows` is whatever
currently survives the 90-day TTL (009_audit_hash_chain.sql), which shrinks as
old rows expire. A checkpoint's row_count has to keep growing even after rows
behind it expire, or a later verifier reading two checkpoints would see counts
go backwards and have no way to tell that apart from deletion -- the exact
failure mode checkpoints exist to rule out. So each run walks forward from the
previous checkpoint's head (not from genesis) and adds only the rows appended
since, carrying the previous row_count forward as a base.
"""

from __future__ import annotations

from dataclasses import dataclass

from .verify_audit import group_key


@dataclass(frozen=True)
class PendingCheckpoint:
    """A checkpoint's unsigned content, ready to hand to the Rust signer."""

    tier: str
    server_id: str
    row_count: int
    head_row_hash: str


class ForkDetectedError(RuntimeError):
    """Raised when two rows in ``rows`` name the same prev_hash.

    verify_audit.verify_tier reports the same condition as a ``fork`` issue,
    and scripts/checkpoint_audit.py never reaches this: it only calls
    compute_next_checkpoint for chains verify_tier has already confirmed
    clean, so a fork there would already have caused the chain to be
    skipped. This exists so a future caller that forgets to self-verify
    first can't silently anchor past a fork by only checking for ``None``.
    """


def compute_next_checkpoint(
    rows: list[dict],
    previous: dict | None,
) -> PendingCheckpoint | None:
    """Compute the next checkpoint for one (tier, server_id) chain.

    ``rows`` must all share the same ``group_key`` (verify_audit.py's
    grouping) and be the chain's currently-stored rows -- not necessarily
    starting at genesis, since earlier rows may already have expired.
    ``previous`` is the chain's most recent prior checkpoint as a dict with
    at least ``row_count`` and ``head_row_hash``, or ``None`` if this chain
    has never been checkpointed.

    Returns ``None`` when there is nothing new to checkpoint: no rows at all,
    or (with a previous checkpoint) no row reachable forward from its head --
    re-signing an unchanged head would not be wrong, but it would make
    verify_audit.py's checkpoint lookups ambiguous about which one is
    "current" without adding any guarantee, so the caller should simply skip
    this chain on this run.

    Walks forward via prev_hash -> row_hash linkage (not ts order) for the
    same reason verify_tier does: same-millisecond ties never mis-order the
    walk. Raises :class:`ForkDetectedError` when two rows name the same
    prev_hash during the walk, rather than silently taking the first-seen
    child and anchoring past the other -- checkpointing a chain that
    verify_audit.py has NOT first confirmed clean is the caller's mistake to
    avoid, not this function's, but this function still refuses rather than
    guessing which branch is real.
    """
    if not rows:
        return None

    children_of: dict[str, list[dict]] = {}
    for row in rows:
        children_of.setdefault(row["prev_hash"], []).append(row)

    start_hash = previous["head_row_hash"] if previous else ""
    base_count = previous["row_count"] if previous else 0

    new_rows = 0
    tip: dict | None = None
    current = start_hash
    while current in children_of:
        children = children_of[current]
        distinct = {child["row_hash"] for child in children}
        if len(distinct) > 1:
            raise ForkDetectedError(
                f"{len(distinct)} rows name prev_hash={current!r}; "
                "verify_tier should have caught this as a fork issue before checkpointing"
            )
        tip = children[0]
        new_rows += 1
        current = tip["row_hash"]

    if tip is None:
        return None

    tier, server_id = group_key(rows[0])
    return PendingCheckpoint(
        tier=tier,
        server_id=server_id,
        row_count=base_count + new_rows,
        head_row_hash=tip["row_hash"],
    )


def rows_unreachable_from_previous(rows: list[dict], previous: dict | None) -> set[str]:
    """``row_hash`` values in ``rows`` that cannot be reached by walking
    forward from ``previous``'s head.

    Used when ``compute_next_checkpoint`` returns ``None``: that alone only
    means no row chains forward from the previous head, which also happens
    whenever the chain is simply unchanged. This tells the caller whether
    there are rows present that are neither the previous head itself nor
    reachable from it -- rows that showed up without ever chaining onto the
    already-checkpointed head, which the first-seen-child walk above would
    otherwise ignore rather than flag.

    Rows behind the previous head (its ancestors still inside the TTL) are
    not stray either: a chain with no new rows since the last checkpoint is
    the normal idle case, not tampering, so walk backward from the previous
    head via prev_hash and exclude everything still on that path too.
    """
    if previous is None:
        return set()
    children_of: dict[str, list[dict]] = {}
    by_hash: dict[str, dict] = {}
    for row in rows:
        children_of.setdefault(row["prev_hash"], []).append(row)
        by_hash[row["row_hash"]] = row
    reachable: set[str] = set()
    stack = list(children_of.get(previous["head_row_hash"], []))
    while stack:
        row = stack.pop()
        if row["row_hash"] in reachable:
            continue
        reachable.add(row["row_hash"])
        stack.extend(children_of.get(row["row_hash"], []))
    head_hash = previous["head_row_hash"]
    ancestors: set[str] = set()
    cur = head_hash
    while cur in by_hash and cur not in ancestors:
        ancestors.add(cur)
        cur = by_hash[cur]["prev_hash"]
    return {r["row_hash"] for r in rows if r["row_hash"] != head_hash} - reachable - ancestors
