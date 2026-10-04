"""Append-only object-book history (MEC-992). Pure diff, no I/O.

Mirrors policy_versions.py: this module decides, deterministically and
without touching ClickHouse, which per-device object books from a fresh
collection pass represent a genuine content change and therefore need a new
ssdf.object_book_hash row; the caller (chwriter.py) does the actual read of
the last-known hash and the INSERT. Cutting history at object-book changes
(not just rule changes) is what MEC-570's later calibration work needs this
table for -- an address-set gaining a member changes what a rule matches even
though the rule's own content_hash (policy_versions.py) is unchanged.
"""

from __future__ import annotations

import hashlib
import json


def content_hash(object_book: dict) -> str:
    """Stable hash over one device's full resolved object book."""
    payload = json.dumps(object_book, sort_keys=True)
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()


def diff_new_object_books(
    collected: list[dict], last_hash_by_key: dict[tuple[str, str], str]
) -> list[dict]:
    """Return one append-row per device whose object-book content hash changed
    (or is new).

    ``collected`` is the list of `{"provider", "device_name", "collected_at",
    "object_book"}` dicts produced by a collector's `collect_objects`.
    ``last_hash_by_key`` maps ``(provider, device_name) -> content_hash`` from
    the latest known ssdf.object_book_hash row, or is missing the key entirely
    for a device never seen before (also produces a new row: its first
    version).
    """
    rows: list[dict] = []
    for item in collected:
        key = (item["provider"], item["device_name"])
        new_hash = content_hash(item["object_book"])
        if last_hash_by_key.get(key) == new_hash:
            continue
        rows.append(
            {
                "provider": item["provider"],
                "device_name": item["device_name"],
                "valid_from": item["collected_at"],
                "content_hash": new_hash,
                "object_book": json.dumps(item["object_book"], sort_keys=True),
            }
        )
    return rows
