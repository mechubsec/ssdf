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
