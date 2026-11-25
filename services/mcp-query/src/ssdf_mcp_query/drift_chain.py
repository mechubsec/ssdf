"""Pure helpers for the per-server policy-drift hash chain (ssdf.policy_drift).

No I/O. mecintent writes rows and SSDF verifies them with these same functions;
the known-answer vectors in tests/fixtures were computed with jq + sha256sum.
"""

from __future__ import annotations

import hashlib
import json

from ssdf_mcp_query.audit_chain import dedup_token, ts_ms_iso

__all__ = ["VERDICTS", "canonical", "compute_row_hash", "dedup_token"]

# Stored with an underscore (the issue's "over-permissive" is `over_permissive`).
VERDICTS = frozenset({"consistent", "violating", "over_permissive", "unverifiable"})


def canonical(row: dict) -> str:
    """Deterministic serialization of a drift row's non-hash fields, in fixed order.

    Raises ValueError if the verdict is not in VERDICTS.
    """
    if row["verdict"] not in VERDICTS:
        raise ValueError(f"unknown drift verdict: {row['verdict']!r}")
    return json.dumps(
        [
            ts_ms_iso(row["ts"]),
            row["server_id"],
            row["intent_commit"],
            row["flow_or_isolation_id"],
            row["verdict"],
            row["device"],
            list(row["device_rule_ids"]),
            row["evidence_ref"],
            int(row["labmode"]),
        ],
        separators=(",", ":"),
        ensure_ascii=False,
    )


def compute_row_hash(prev_hash: str, row: dict) -> str:
    """row_hash = SHA-256( prev_hash + '\\n' + canonical(row) ), hex. Genesis prev_hash is ''."""
    return hashlib.sha256((prev_hash + "\n" + canonical(row)).encode("utf-8")).hexdigest()
