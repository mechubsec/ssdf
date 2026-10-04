"""ClickHouse writer for configured entities/edges into the shared M6a tables."""

from __future__ import annotations

from typing import Any, Iterable

import clickhouse_connect

from ssdf_common.clickhouse import client_kwargs as _client_kwargs
from .config import Config
from .object_book import diff_new_object_books
from .policy_versions import diff_new_versions, version_key

# Byte-identical to services/entity/src/ssdf_entity/chwriter.py column orders.
ENTITY_COLUMNS = [
    "entity_id",
    "tenant_id",
    "kind",
    "name",
    "identifiers",
    "source",
    "identity_basis",
    "confidence",
    "attrs",
    "first_seen",
    "last_seen",
]
ENTITY_EDGE_COLUMNS = [
    "edge_id",
    "tenant_id",
    "src_id",
    "dst_id",
    "edge_type",
    "source",
    "confidence",
    "attrs",
    "first_seen",
    "last_seen",
]


def client_kwargs(config: Config) -> dict[str, Any]:
    """get_client kwargs from config; adds TLS (interface/ca_cert) when ch_secure."""
    return _client_kwargs(
        host=config.ch_host,
        port=config.ch_port,
        user=config.ch_user,
        password=config.ch_password.get(),
        database=config.ch_database,
        secure=config.ch_secure,
        ca_file=config.ch_ca_file,
    )


def entity_rows(entities: Iterable[dict]) -> list[list[Any]]:
    return [[e[c] for c in ENTITY_COLUMNS] for e in entities]


def edge_rows(edges: Iterable[dict]) -> list[list[Any]]:
    return [[e[c] for c in ENTITY_EDGE_COLUMNS] for e in edges]


class ClickHouseEntityWriter:
    """Upserts configured entities/edges (ReplacingMergeTree dedups by id on merge)."""

    def __init__(self, config: Config):
        self._config = config
        self._client = clickhouse_connect.get_client(**client_kwargs(config))

    def replace_entities(self, entities: list[dict]) -> int:
        if not entities:
            return 0
        self._client.insert("entities", entity_rows(entities), column_names=ENTITY_COLUMNS)
        return len(entities)

    def replace_edges(self, edges: list[dict]) -> int:
        if not edges:
            return 0
        self._client.insert("entity_edges", edge_rows(edges), column_names=ENTITY_EDGE_COLUMNS)
        return len(edges)

    def append_policy_versions(self, policy_entities: list[dict]) -> int:
        """Append one ssdf.policy_versions row per policy whose content actually
        changed since its last known version (MEC-566). Read (last hash per rule)
        + diff (pure, policy_versions.diff_new_versions) + INSERT -- never UPDATE
        or DELETE, matching the append-only pattern in 007_audit.sql."""
        if not policy_entities:
            return 0
        keys = [version_key(p) for p in policy_entities]
        last_hash_by_key = self._fetch_latest_hashes(keys)
        versions = diff_new_versions(policy_entities, last_hash_by_key)
        if not versions:
            return 0
        self._client.insert(
            "policy_versions",
            [[v[c] for c in POLICY_VERSION_COLUMNS] for v in versions],
            column_names=POLICY_VERSION_COLUMNS,
        )
        return len(versions)

    def append_object_book_hashes(self, collected: list[dict]) -> int:
        """Append one ssdf.object_book_hash row per device whose resolved
        object book changed since its last known hash (MEC-992). Same
        read+diff+INSERT pattern as append_policy_versions, never UPDATE or
        DELETE."""
        if not collected:
            return 0
        keys = [(item["provider"], item["device_name"]) for item in collected]
        last_hash_by_key = self._fetch_latest_object_book_hashes(keys)
        rows = diff_new_object_books(collected, last_hash_by_key)
        if not rows:
            return 0
        for row in rows:
            row.setdefault("tenant_id", self._config.tenant_id)
        self._client.insert(
            "object_book_hash",
            [[row[c] for c in OBJECT_BOOK_HASH_COLUMNS] for row in rows],
            column_names=OBJECT_BOOK_HASH_COLUMNS,
        )
        return len(rows)

    def _fetch_latest_object_book_hashes(self, keys: list[tuple[str, str]]) -> dict:
        if not keys:
            return {}
        providers = sorted({k[0] for k in keys})
        devices = sorted({k[1] for k in keys})
        result = self._client.query(
            "SELECT provider, device_name, "
            "argMax(content_hash, valid_from) AS content_hash "
            "FROM object_book_hash "
            "WHERE provider IN {providers:Array(String)} "
            "AND device_name IN {devices:Array(String)} "
            "GROUP BY provider, device_name",
            parameters={"providers": providers, "devices": devices},
        )
        return {(row[0], row[1]): row[2] for row in result.result_rows}

    def _fetch_latest_hashes(self, keys: list[tuple[str, str, str]]) -> dict:
        if not keys:
            return {}
        providers = sorted({k[0] for k in keys})
        devices = sorted({k[1] for k in keys})
        rules = sorted({k[2] for k in keys})
        result = self._client.query(
            "SELECT provider, device_name, rule_name, "
            "argMax(content_hash, valid_from) AS content_hash "
            "FROM policy_versions "
            "WHERE provider IN {providers:Array(String)} "
            "AND device_name IN {devices:Array(String)} "
            "AND rule_name IN {rules:Array(String)} "
            "GROUP BY provider, device_name, rule_name",
            parameters={"providers": providers, "devices": devices, "rules": rules},
        )
        return {(row[0], row[1], row[2]): row[3] for row in result.result_rows}


POLICY_VERSION_COLUMNS = [
    "tenant_id",
    "provider",
    "device_name",
    "rule_name",
    "valid_from",
    "content_hash",
    "action",
    "from_zone",
    "to_zone",
    "enabled",
    "position",
]

OBJECT_BOOK_HASH_COLUMNS = [
    "tenant_id",
    "provider",
    "device_name",
    "valid_from",
    "content_hash",
    "object_book",
]
