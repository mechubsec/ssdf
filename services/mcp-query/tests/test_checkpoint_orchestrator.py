from __future__ import annotations

import datetime as dt

import pytest

from ssdf_mcp_query.audit_chain import compute_row_hash
from ssdf_mcp_query.checkpoint_orchestrator import (
    ForkDetectedError,
    compute_next_checkpoint,
    rows_unreachable_from_previous,
)


def _chain(n, tier="sovereign", first_prev=""):
    rows = []
    prev = first_prev
    for i in range(n):
        row = dict(
            ts=dt.datetime(2026, 6, 10, 12, 0, i, 0, tzinfo=dt.timezone.utc),
            principal="agent",
            tier=tier,
            tool=f"t{i}",
            args="{}",
            data_classes=["topology"],
            decision="allow",
            row_count=i,
            error="",
        )
        row["prev_hash"] = prev
        row["row_hash"] = compute_row_hash(prev, row)
        prev = row["row_hash"]
        rows.append(row)
    return rows


def test_no_rows_yields_no_checkpoint():
    assert compute_next_checkpoint([], previous=None) is None


def test_first_checkpoint_walks_from_genesis():
    rows = _chain(4)
    cp = compute_next_checkpoint(rows, previous=None)
    assert cp is not None
    assert cp.tier == "sovereign"
    assert cp.server_id == ""
    assert cp.row_count == 4
    assert cp.head_row_hash == rows[-1]["row_hash"]


def test_second_checkpoint_counts_only_new_rows_since_the_last_one():
    first_run = _chain(4)
    previous = {"row_count": 4, "head_row_hash": first_run[-1]["row_hash"]}

    second_run = _chain(3, first_prev=first_run[-1]["row_hash"])
    # Simulate the earliest rows of first_run having expired out of ssdf.audit
    # by only passing the still-live tail plus the new rows.
    still_live = [first_run[-1]] + second_run

    cp = compute_next_checkpoint(still_live, previous)
    assert cp is not None
    assert cp.row_count == 4 + 3  # base + 3 new rows, NOT len(still_live)
    assert cp.head_row_hash == second_run[-1]["row_hash"]


def test_no_new_rows_since_previous_checkpoint_yields_none():
    rows = _chain(4)
    previous = {"row_count": 4, "head_row_hash": rows[-1]["row_hash"]}
    # Only the already-checkpointed tip survives; nothing new appended.
    cp = compute_next_checkpoint([rows[-1]], previous)
    assert cp is None


def test_previous_checkpoint_head_fully_expired_yields_none_not_a_guess():
    """If the previous checkpoint's head row itself has expired out of
    ssdf.audit and no later row chains from it either, there is nothing this
    run can honestly extend -- it must not guess at a row_count."""
    rows = _chain(3, first_prev="deadbeef-stale-checkpoint-head")
    previous = {"row_count": 10, "head_row_hash": "deadbeef-stale-checkpoint-head-does-not-match"}
    assert compute_next_checkpoint(rows, previous) is None


def test_a_forked_chain_raises_instead_of_picking_a_branch():
    """Two rows naming the same prev_hash must refuse the walk rather than
    silently taking the first-seen child and anchoring past the other."""
    rows = _chain(2)
    genuine_child = rows[-1]
    sibling = dict(genuine_child, tool="sibling", row_count=99)
    sibling["row_hash"] = compute_row_hash(sibling["prev_hash"], sibling)
    rows.append(sibling)

    with pytest.raises(ForkDetectedError):
        compute_next_checkpoint(rows, previous=None)


def test_rows_unreachable_from_previous_is_empty_with_no_previous():
    rows = _chain(2)
    assert rows_unreachable_from_previous(rows, None) == set()


def test_rows_unreachable_from_previous_is_empty_when_chain_extends_cleanly():
    first_run = _chain(2)
    previous = {"row_count": 2, "head_row_hash": first_run[-1]["row_hash"]}
    second_run = _chain(2, first_prev=first_run[-1]["row_hash"])
    still_live = first_run + second_run

    assert rows_unreachable_from_previous(still_live, previous) == set()


def test_rows_unreachable_from_previous_is_empty_for_an_idle_chain():
    """A chain with no new rows since the last checkpoint is the normal
    idle case: the previous head's still-live ancestors must not be
    flagged as stray just because they are not reachable *forward* from
    that head."""
    rows = _chain(2)
    previous = {"row_count": 2, "head_row_hash": rows[-1]["row_hash"]}

    assert rows_unreachable_from_previous(rows, previous) == set()


def test_rows_unreachable_from_previous_flags_rows_that_never_chained_from_the_head():
    """A row that appears in the chain's current rows without chaining
    forward from the previous checkpoint's head -- e.g. the real branch
    continuing a fork's genesis while the checkpoint head sits on the
    fork's other, now-abandoned branch -- must be flagged rather than
    treated the same as "nothing new"."""
    rows = _chain(1)
    genesis = rows[0]
    fork_head = dict(genesis, tool="fork-head", row_count=50)
    fork_head["row_hash"] = compute_row_hash(genesis["prev_hash"], fork_head)
    previous = {"row_count": 1, "head_row_hash": fork_head["row_hash"]}

    real_branch = _chain(2, first_prev=genesis["row_hash"])
    current_rows = [genesis] + real_branch

    stray = rows_unreachable_from_previous(current_rows, previous)
    assert stray == {r["row_hash"] for r in current_rows}


def test_evidence_chain_carries_its_writer_id():
    row = dict(
        ts=dt.datetime(2026, 8, 20, 12, 0, 0, 0, tzinfo=dt.timezone.utc),
        principal="agent:mecmcp",
        tier="evidence",
        tool="evidence:proposal",
        args='{"server_id":"rustsdcmcp-606","run_id":"run-1","segment_seq":0}',
        data_classes=["device:vsrx-ci"],
        decision="",
        row_count=1,
        error="",
        prev_hash="",
    )
    row["row_hash"] = compute_row_hash("", row)
    cp = compute_next_checkpoint([row], previous=None)
    assert cp.tier == "evidence"
    assert cp.server_id == "rustsdcmcp-606"
    assert cp.row_count == 1
