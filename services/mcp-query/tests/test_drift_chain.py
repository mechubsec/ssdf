"""Drift-row hash: vectors were produced by scripts/gen_drift_vectors.sh (jq + sha256sum)."""

import datetime as dt
import json
from pathlib import Path

import pytest

from ssdf_mcp_query.drift_chain import VERDICTS, canonical, compute_row_hash

VECTORS = json.loads((Path(__file__).parent / "fixtures" / "drift_chain_vectors.json").read_text())


def _row(vector_row: dict) -> dict:
    return {**vector_row, "ts": dt.datetime.fromisoformat(vector_row["ts"].replace("Z", "+00:00"))}


@pytest.mark.parametrize("vector", VECTORS)
def test_vectors_reproduce(vector):
    row = _row(vector["row"])
    assert canonical(row) == vector["canonical"]
    assert compute_row_hash(vector["prev_hash"], row) == vector["row_hash"]


def test_chain_links():
    assert VECTORS[1]["prev_hash"] == VECTORS[0]["row_hash"]
    assert VECTORS[0]["prev_hash"] == ""


def test_unknown_verdict_rejected():
    row = _row(VECTORS[0]["row"])
    row["verdict"] = "over-permissive"
    assert "over_permissive" in VERDICTS
    with pytest.raises(ValueError):
        canonical(row)


def test_ts_truncates_to_ms():
    row = _row(VECTORS[0]["row"])
    row["ts"] = dt.datetime(2026, 11, 24, 10, 0, 0, 123999, tzinfo=dt.timezone.utc)
    assert json.loads(canonical(row))[0] == "2026-11-24T10:00:00.123Z"


_CHANGES = {
    "ts": dt.datetime(2026, 11, 24, 10, 0, 0, 124000, tzinfo=dt.timezone.utc),
    "server_id": "srv-b.example.com",
    "intent_commit": "fedcba9",
    "flow_or_isolation_id": "flow-9",
    "verdict": "violating",
    "device": "fw9.example.com",
    "device_rule_ids": ["r1"],
    "evidence_ref": "ev/other",
    "labmode": 0,
}


@pytest.mark.parametrize("field", list(_CHANGES))
def test_any_field_change_changes_hash(field):
    row = _row(VECTORS[0]["row"])
    assert _CHANGES[field] != row[field]
    changed = {**row, field: _CHANGES[field]}
    assert compute_row_hash("", changed) != compute_row_hash("", row)
