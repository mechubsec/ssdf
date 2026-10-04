"""Resolve normalized firewall rules into Firewall + configured-Policy entities and edges.

Pure, deterministic. Snapshot semantics: first_seen == last_seen == collected_at (latest
config pull wins under ReplacingMergeTree(last_seen); no rule-version history — see spec §6).
"""

from __future__ import annotations

from .models import (
    FIREWALL,
    POLICY,
    GOVERNED_BY,
    CONFIGURED,
    entity_id,
    edge_id,
)


def _join(values: list[str]) -> str:
    """Comma-join a list for storage in a Map(String, String) attr."""
    return ",".join(v for v in values if v)


def resolve_policies(rules: list[dict], tenant: str) -> tuple[list[dict], list[dict]]:
    entities: dict[str, dict] = {}
    edges: dict[str, dict] = {}

    def firewall_for(provider: str, device: str, seen: str) -> dict:
        eid = entity_id(tenant, FIREWALL, f"device:{device}")
        fw = entities.get(eid)
        if fw is None:
            fw = {
                "entity_id": eid,
                "tenant_id": tenant,
                "kind": FIREWALL,
                "name": device,
                "identifiers": {"device_name": device},
                "source": CONFIGURED,
                "identity_basis": "device_name",
                "confidence": 1.0,
                "attrs": {"provider": provider, "rule_count": "0"},
                "first_seen": seen,
                "last_seen": seen,
            }
            entities[eid] = fw
        fw["attrs"]["rule_count"] = str(int(fw["attrs"]["rule_count"]) + 1)
        return fw

    for rule in rules:
        provider = rule["provider"]
        device = rule["device_name"]
        name = rule["rule_name"]
        seen = rule["collected_at"]
        fw = firewall_for(provider, device, seen)

        pol_eid = entity_id(tenant, POLICY, f"{provider}:{device}:{name}")
        attrs = {
            "provider": provider,
            "device_name": device,
            "action": rule["action"],
            "from_zone": _join(rule["from_zone"]),
            "to_zone": _join(rule["to_zone"]),
            "source_addresses": _join(rule["source_addresses"]),
            "dest_addresses": _join(rule["dest_addresses"]),
            "application": _join(rule["application"]),
            "service": _join(rule["service"]),
            "position": str(rule["position"]),
            "enabled": "true" if rule["enabled"] else "false",
        }
        # MEC-992: surface the previously-dropped match clauses (and the PAN-OS
        # negate/schedule bindings) on the entity itself, so a rule using one
        # is visibly flagged rather than silently indistinguishable from a
        # rule that matches everything.
        if "match_unknown" in rule:
            attrs["match_unknown"] = "true" if rule["match_unknown"] else "false"
            attrs["source_address_excluded"] = (
                "true" if rule["source_address_excluded"] else "false"
            )
            attrs["dest_address_excluded"] = "true" if rule["dest_address_excluded"] else "false"
            attrs["source_identity"] = _join(rule["source_identity"])
            attrs["dynamic_application"] = _join(rule["dynamic_application"])
            attrs["url_category"] = _join(rule["url_category"])
            attrs["source_end_user_profile"] = _join(rule["source_end_user_profile"])
            attrs["scheduler_name"] = rule["scheduler_name"]
        if "negate_source" in rule:
            attrs["negate_source"] = "true" if rule["negate_source"] else "false"
            attrs["negate_destination"] = "true" if rule["negate_destination"] else "false"
            attrs["schedule"] = rule["schedule"]
        if "is_global" in rule:
            # Persist the collector's own classification rather than making
            # change_impact re-derive it from from_zone later: a Junos global
            # policy can carry an explicit `match from-zone X`, which an
            # `from_zone == "any"` heuristic would misclassify as a zone-pair
            # rule.
            attrs["is_global"] = "true" if rule["is_global"] else "false"
        attrs.update(rule.get("vendor_extras") or {})
        policy = {
            "entity_id": pol_eid,
            "tenant_id": tenant,
            "kind": POLICY,
            "name": name,
            "identifiers": {"rule": name, "provider": provider, "device_name": device},
            "source": CONFIGURED,
            "identity_basis": "",
            "confidence": 1.0,
            "attrs": attrs,
            "first_seen": seen,
            "last_seen": seen,
        }
        entities[pol_eid] = policy

        gov_eid = edge_id(tenant, fw["entity_id"], pol_eid, GOVERNED_BY, CONFIGURED)
        edges[gov_eid] = {
            "edge_id": gov_eid,
            "tenant_id": tenant,
            "src_id": fw["entity_id"],
            "dst_id": pol_eid,
            "edge_type": GOVERNED_BY,
            "source": CONFIGURED,
            "confidence": 1.0,
            "attrs": {"rule": name, "provider": provider},
            "first_seen": seen,
            "last_seen": seen,
        }

    return list(entities.values()), list(edges.values())
