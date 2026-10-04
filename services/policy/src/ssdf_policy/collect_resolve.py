"""Entrypoint: collect configured rules from each firewall, resolve, upsert entities/edges."""

from __future__ import annotations

import datetime
import logging
import os

from . import collectors  # noqa: F401 — triggers @register for panos+junos
from .chwriter import ClickHouseEntityWriter
from .collectors.base import REGISTRY
from .config import Config, load_config
from .mcp_client import McpToolClient
from .models import POLICY
from .resolve_policies import resolve_policies

log = logging.getLogger("ssdf_policy.collect_resolve")


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds")


def _build_collector(name: str):
    cls = REGISTRY[name]
    if name == "junos":
        raw = os.environ.get("JUNOS_DEVICES", "")
        return cls(devices=[d.strip() for d in raw.split(",") if d.strip()])
    if name == "panos":
        return cls(device=os.environ.get("PANOS_DEVICE", "panosvm"))
    return cls()


def run_once(
    enabled,
    collector_factory,
    client_factory,
    writer,
    tenant: str,
    now: str,
    version_writer=None,
) -> tuple[int, int]:
    """Collect rules from each enabled firewall (skipping failures), resolve, write.

    ``version_writer``, when given, appends ssdf.policy_versions rows for any
    configured-policy entity whose content changed since its last known version
    (MEC-566), and ssdf.object_book_hash rows for any device whose resolved
    address/application/service object book changed (MEC-992). Optional and
    additive: existing callers that omit it are unchanged.
    """
    all_rules: list[dict] = []
    all_object_books: list[dict] = []
    for name in enabled:
        try:
            collector = collector_factory(name)
            client = client_factory(name)
            all_rules.extend(collector.collect(client, now))
        except Exception:
            log.warning("policy collector %r failed; skipping", name, exc_info=True)
            continue
        # MEC-992: object-book collection is additive and independent of rule
        # collection -- a failure here must not be mistaken for the rules
        # themselves failing to collect (all_rules above already has them).
        collect_objects = getattr(collector, "collect_objects", None)
        if collect_objects is not None:
            try:
                all_object_books.extend(collect_objects(client, now))
            except Exception:
                log.warning(
                    "policy collector %r: object book collection failed; skipping",
                    name,
                    exc_info=True,
                )
    entities, edges = resolve_policies(all_rules, tenant)
    n_ent = writer.replace_entities(entities)
    n_edge = writer.replace_edges(edges)
    if version_writer is not None:
        policies = [e for e in entities if e["kind"] == POLICY]
        try:
            n_ver = version_writer.append_policy_versions(policies)
            log.info("policy resolver: %d policy_versions rows appended", n_ver)
        except Exception:
            # Versioning is additive history, not the primary write path: a
            # failure here must not be mistaken for "the configured policy
            # itself failed to resolve/write" (n_ent/n_edge above already
            # succeeded and are returned regardless).
            log.warning("policy_versions append failed; continuing", exc_info=True)
        try:
            n_obj = version_writer.append_object_book_hashes(all_object_books)
            log.info("policy resolver: %d object_book_hash rows appended", n_obj)
        except Exception:
            log.warning("object_book_hash append failed; continuing", exc_info=True)
    log.info("policy resolver: %d entities, %d edges upserted", n_ent, n_edge)
    return n_ent, n_edge


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    config: Config = load_config()
    writer = ClickHouseEntityWriter(config)
    run_once(
        enabled=config.enabled_collectors,
        collector_factory=_build_collector,
        client_factory=lambda name: McpToolClient(config.mcp_endpoint(name)),
        writer=writer,
        tenant=config.tenant_id,
        now=_now(),
        version_writer=writer,  # ClickHouseEntityWriter also implements append_policy_versions
    )


if __name__ == "__main__":
    main()
