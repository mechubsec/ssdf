"""Offline tamper-evidence verifier for the ssdf.policy_drift hash chain.

One chain per ``server_id`` (a row from writer B must never link into writer
A's chain). Unlike evidence rows, every drift row is recomputed here. Issue
types reuse ``verify_audit``'s vocabulary: ``content_edit``,
``missing_predecessor``, ``duplicate_row``, ``fork``; plus ``invalid_verdict``.

A chain whose earliest row names a predecessor that exists nowhere has had its
genesis expired by the table TTL: reported as ``anchored: false``, not an issue.
"""

from __future__ import annotations

import sys
from collections import defaultdict

from .config import load_config
from .drift_chain import VERDICTS, compute_row_hash
from .verify_audit import _make_client

_COLUMNS = [
    "ts",
    "server_id",
    "intent_commit",
    "flow_or_isolation_id",
    "verdict",
    "device",
    "device_rule_ids",
    "evidence_ref",
    "labmode",
    "prev_hash",
    "row_hash",
]


def _issue(kind: str, row: dict) -> dict:
    return {"type": kind, "server_id": row["server_id"], "row_hash": row["row_hash"]}


def verify_chains(rows: list[dict]) -> dict:
    """Verify drift rows; returns ``{"chains": {...}, "issues": [...], "ok": bool}``."""
    by_server: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        by_server[row["server_id"]].append(row)
    owner_of_hash = {row["row_hash"]: row["server_id"] for row in rows}

    chains: dict[str, dict] = {}
    issues: list[dict] = []
    for server_id, chain_rows in sorted(by_server.items()):
        own_hashes = {r["row_hash"] for r in chain_rows}
        pointed_at = {r["prev_hash"] for r in chain_rows}
        # Structure, not ts: tied timestamps come back from ClickHouse in any order.
        # Roots are rows with no predecessor in this chain; a real genesis wins,
        # then the earliest ts, then row_hash, so the choice is deterministic.
        roots = [r for r in chain_rows if r["prev_hash"] == "" or r["prev_hash"] not in own_hashes]
        root = min(roots, key=lambda r: (r["prev_hash"] != "", r["ts"], r["row_hash"]))
        tips = [r for r in chain_rows if r["row_hash"] not in pointed_at] or chain_rows
        head = max(tips, key=lambda r: (r["ts"], r["row_hash"]))
        chains[server_id] = {
            "rows": len(chain_rows),
            "head": head["row_hash"],
            "anchored": root["prev_hash"] == "",
        }

        counts: dict[str, int] = defaultdict(int)
        children: dict[str, set[str]] = defaultdict(set)
        for row in chain_rows:
            counts[row["row_hash"]] += 1
            children[row["prev_hash"]].add(row["row_hash"])
        by_hash = {r["row_hash"]: r for r in chain_rows}

        for row_hash, count in counts.items():
            if count > 1:
                issues.append(_issue("duplicate_row", by_hash[row_hash]))

        for siblings in children.values():
            if len(siblings) > 1:
                issues.extend(_issue("fork", by_hash[h]) for h in siblings)

        for row in chain_rows:
            if row["verdict"] not in VERDICTS:
                issues.append(_issue("invalid_verdict", row))
            elif compute_row_hash(row["prev_hash"], row) != row["row_hash"]:
                issues.append(_issue("content_edit", row))

        for row in chain_rows:
            prev_hash = row["prev_hash"]
            if prev_hash == "" or prev_hash in own_hashes:
                continue
            # Another writer's hash is always a break; an unknown one is only
            # tolerated on the chain's root (genesis aged out by TTL).
            if prev_hash in owner_of_hash or row is not root:
                issues.append(_issue("missing_predecessor", row))

    return {"chains": chains, "issues": issues, "ok": not issues}


def fetch_rows(config) -> list[dict]:
    """Read ssdf.policy_drift as the read-only ssdf_audit_verify identity."""
    client = _make_client(config)
    res = client.query(
        f"SELECT {', '.join(_COLUMNS)} FROM ssdf.policy_drift ORDER BY server_id, ts"
    )
    return [dict(zip(_COLUMNS, values)) for values in res.result_rows]


def main(argv: list[str] | None = None) -> int:
    """Print per-chain summary and issues; return 1 if any issue, 2 if unconfigured."""
    config = load_config()
    if not config.ch_audit_verify_password:
        print("CH_AUDIT_VERIFY_PASSWORD is required to verify the drift chain", file=sys.stderr)
        return 2
    result = verify_chains(fetch_rows(config))
    for server_id, chain in result["chains"].items():
        print(
            f"server={server_id} rows={chain['rows']} head={chain['head'][:16]}… "
            f"anchored={str(chain['anchored']).lower()}"
        )
    for issue in result["issues"]:
        print(f"  {issue['type']}: server={issue['server_id']} row_hash={issue['row_hash'][:16]}…")
    print("OK" if result["ok"] else f"{len(result['issues'])} ISSUE(S)")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
