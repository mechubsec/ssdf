"""Pin scripts/verify_drift_contract.py's embedded helpers to the shared vectors.

The script is standalone (stdlib only) and cannot import the package, so it
carries copies of the hash helpers. These tests are what keeps the copies honest.
"""

import datetime as dt
import importlib.util
import json
from pathlib import Path

import pytest

from ssdf_mcp_query.drift_chain import dedup_token as package_dedup_token

_ROOT = Path(__file__).resolve().parents[3]
_SPEC = importlib.util.spec_from_file_location(
    "verify_drift_contract", _ROOT / "scripts" / "verify_drift_contract.py"
)
script = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(script)

VECTORS = json.loads((Path(__file__).parent / "fixtures" / "drift_chain_vectors.json").read_text())


def _row(vector_row: dict) -> dict:
    return {**vector_row, "ts": dt.datetime.fromisoformat(vector_row["ts"].replace("Z", "+00:00"))}


@pytest.mark.parametrize("vector", VECTORS)
def test_embedded_hash_matches_vectors(vector):
    row = _row(vector["row"])
    assert script.canonical(row) == vector["canonical"]
    assert script.compute_row_hash(vector["prev_hash"], row) == vector["row_hash"]


@pytest.mark.parametrize(
    "args",
    [("srv-a.example.com", "run-1", 0), ("a:b", "c", 1), ("a", "b:c", 1), ("café", "run-é", 7)],
)
def test_embedded_dedup_token_matches_package(args):
    assert script.dedup_token(*args) == package_dedup_token(*args)


def test_non_loopback_host_refused():
    with pytest.raises(SystemExit):
        script.require_loopback("198.51.100.7")


def _chain(count, *, tied_ts=True, genesis_prev=""):
    """Build a valid chain of ``count`` rows; tied timestamps unless asked otherwise."""
    rows, prev = [], genesis_prev
    for index in range(count):
        ts = dt.datetime(2026, 11, 24, 10, 0, 0, 123000, tzinfo=dt.timezone.utc)
        if not tied_ts:
            ts += dt.timedelta(seconds=index)
        row = {
            **_row(VECTORS[0]["row"]),
            "ts": ts,
            "evidence_ref": f"ev/{index}",
            "prev_hash": prev,
        }
        row["row_hash"] = script.compute_row_hash(prev, row)
        rows.append(row)
        prev = row["row_hash"]
    return rows


@pytest.mark.parametrize("reverse", [False, True])
def test_tied_ts_chain_structural_root_and_head(reverse):
    rows = _chain(3)
    summary, problems = script.verify_chain(rows[::-1] if reverse else rows)
    assert problems == []
    assert summary["anchored"] is True
    assert summary["head"] == rows[-1]["row_hash"]


@pytest.mark.parametrize("reverse", [False, True])
def test_aged_out_genesis_is_unanchored_not_an_issue(reverse):
    rows = _chain(3, genesis_prev="f" * 64)
    summary, problems = script.verify_chain(rows[::-1] if reverse else rows)
    assert problems == []
    assert summary["anchored"] is False
    assert summary["head"] == rows[-1]["row_hash"]


def test_fork_is_reported():
    rows = _chain(2)
    sibling = {**rows[1], "evidence_ref": "ev/other"}
    sibling["row_hash"] = script.compute_row_hash(sibling["prev_hash"], sibling)
    _, problems = script.verify_chain([*rows, sibling])
    assert {kind for kind, _ in problems} == {"fork"}


def test_cycle_does_not_raise():
    first, second = _chain(2)
    first["prev_hash"], second["prev_hash"] = second["row_hash"], first["row_hash"]
    _, problems = script.verify_chain([first, second])
    assert problems  # hashes no longer recompute; the point is that it returns


def test_resolve_head_rule():
    ts = dt.datetime(2026, 11, 24, tzinfo=dt.timezone.utc)
    one = ("a" * 64, ts)
    assert script.resolve_head(0, []) == ("", None)
    assert script.resolve_head(1, [one]) == one
    assert script.resolve_head(2, [one, one]) == one  # a duplicated tail is one head
    with pytest.raises(SystemExit):
        script.resolve_head(2, [])  # rows but no head: a rootless cycle
    with pytest.raises(SystemExit):
        script.resolve_head(2, [one, ("b" * 64, ts)])


def test_next_ts_clamps_a_clock_behind_the_head():
    head = dt.datetime(2026, 11, 24, 10, 0, tzinfo=dt.timezone.utc)
    behind = head - dt.timedelta(seconds=5)
    ahead = head + dt.timedelta(seconds=5)
    assert script.next_ts(behind, head) == head
    assert script.next_ts(ahead, head) == ahead
    assert script.next_ts(behind, None) == behind
