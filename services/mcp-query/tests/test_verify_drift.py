"""Offline verifier for the ssdf.policy_drift hash chain (no ClickHouse)."""

import datetime as dt

import pytest

from ssdf_mcp_query import verify_drift
from ssdf_mcp_query.drift_chain import compute_row_hash
from ssdf_mcp_query.verify_drift import verify_chains

T0 = dt.datetime(2026, 11, 24, 10, 0, 0, tzinfo=dt.timezone.utc)


def _chain(server_id="srv-a.example.com", count=3, prev_hash="", start=0):
    rows = []
    for index in range(start, start + count):
        row = {
            "ts": T0 + dt.timedelta(seconds=index),
            "server_id": server_id,
            "intent_commit": "0123abc",
            "flow_or_isolation_id": f"flow-{index}",
            "verdict": "consistent",
            "device": "fw1.example.com",
            "device_rule_ids": ["r1"],
            "evidence_ref": f"ev/{index}",
            "labmode": 1,
            "prev_hash": prev_hash,
        }
        row["row_hash"] = compute_row_hash(prev_hash, row)
        prev_hash = row["row_hash"]
        rows.append(row)
    return rows


def _types(result):
    return sorted(issue["type"] for issue in result["issues"])


def test_clean_chain_is_ok_and_anchored():
    rows = _chain()
    result = verify_chains(rows)
    assert result["ok"] and result["issues"] == []
    assert result["chains"] == {
        "srv-a.example.com": {"rows": 3, "head": rows[-1]["row_hash"], "anchored": True}
    }


def test_content_edit():
    rows = _chain()
    rows[1]["verdict"] = "violating"
    result = verify_chains(rows)
    assert not result["ok"]
    assert _types(result) == ["content_edit"]
    assert result["issues"][0] == {
        "type": "content_edit",
        "server_id": "srv-a.example.com",
        "row_hash": rows[1]["row_hash"],
    }


def test_deleted_middle_row_is_missing_predecessor():
    rows = _chain()
    del rows[1]
    result = verify_chains(rows)
    assert _types(result) == ["missing_predecessor"]
    assert result["issues"][0]["row_hash"] == rows[1]["row_hash"]


def test_fork():
    rows = _chain(count=2)
    sibling = {**rows[1], "evidence_ref": "ev/other", "ts": T0 + dt.timedelta(seconds=9)}
    sibling["row_hash"] = compute_row_hash(sibling["prev_hash"], sibling)
    result = verify_chains(rows + [sibling])
    assert _types(result) == ["fork", "fork"]


def test_replayed_row_is_duplicate():
    rows = _chain()
    result = verify_chains(rows + [dict(rows[2])])
    assert _types(result) == ["duplicate_row"]


def test_interleaved_servers_verify_independently():
    chain_a = _chain("srv-a.example.com")
    chain_b = _chain("srv-b.example.com")
    result = verify_chains([r for pair in zip(chain_a, chain_b) for r in pair])
    assert result["ok"]
    assert set(result["chains"]) == {"srv-a.example.com", "srv-b.example.com"}


def test_cross_chain_link_is_flagged_even_for_earliest_row():
    chain_a = _chain("srv-a.example.com")
    chain_b = _chain("srv-b.example.com", prev_hash=chain_a[0]["row_hash"])
    result = verify_chains(chain_a + chain_b)
    assert _types(result) == ["missing_predecessor"]
    assert result["issues"][0]["server_id"] == "srv-b.example.com"


def test_aged_out_genesis_is_unanchored_not_an_issue():
    rows = _chain(prev_hash="f" * 64)
    result = verify_chains(rows)
    assert result["ok"]
    assert result["chains"]["srv-a.example.com"]["anchored"] is False


def test_invalid_verdict_is_an_issue_not_an_exception():
    rows = _chain()
    rows[1]["verdict"] = "over-permissive"
    result = verify_chains(rows)
    assert "invalid_verdict" in _types(result)
    assert not result["ok"]


def test_main_reports_and_exit_code(monkeypatch, capsys):
    monkeypatch.setattr(
        verify_drift, "load_config", lambda: type("C", (), {"ch_audit_verify_password": "x"})()
    )
    monkeypatch.setattr(verify_drift, "fetch_rows", lambda config: _chain())
    assert verify_drift.main([]) == 0
    assert "srv-a.example.com rows=3" in capsys.readouterr().out

    bad = _chain()
    bad[0]["verdict"] = "violating"
    monkeypatch.setattr(verify_drift, "fetch_rows", lambda config: bad)
    assert verify_drift.main([]) == 1
    assert "content_edit" in capsys.readouterr().out


@pytest.mark.parametrize("dangling", [False, True])
@pytest.mark.parametrize("reverse", [False, True])
def test_tied_ts_does_not_change_root_or_head(dangling, reverse):
    rows = _chain(count=3, prev_hash="f" * 64 if dangling else "")
    rows[1]["ts"] = rows[0]["ts"]  # tie; hashes must be recomputed with the new ts
    rows[1]["row_hash"] = compute_row_hash(rows[1]["prev_hash"], rows[1])
    rows[2]["prev_hash"] = rows[1]["row_hash"]
    rows[2]["row_hash"] = compute_row_hash(rows[2]["prev_hash"], rows[2])
    result = verify_chains(rows[::-1] if reverse else rows)
    assert result["ok"], result["issues"]
    chain = result["chains"]["srv-a.example.com"]
    assert chain["anchored"] is (not dangling)
    assert chain["head"] == rows[2]["row_hash"]


@pytest.mark.parametrize("rows", [[]])
def test_empty_is_ok(rows):
    assert verify_chains(rows) == {"chains": {}, "issues": [], "ok": True}
