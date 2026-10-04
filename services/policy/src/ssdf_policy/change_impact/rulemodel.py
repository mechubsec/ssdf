"""Compile `NormalizedRule` dicts (the collectors' shared shape, see
collectors/{junos,panos}.py) plus a resolved object book into rules this
evaluator can test a flow tuple against.

Each `CompiledRule.match(tuple)` returns a `Kleene3`: the AND, in strong
Kleene logic, of every match clause plus a synthetic clause for whatever the
collector already flagged `match_unknown` (source-identity, dynamic-app,
url-category, EUP profile, scheduler-name on Junos; source-user, HIP,
url-category, schedule on PAN-OS -- see doc §1.2). Kleene AND means a rule
that plainly fails on a *known* field (wrong zone, wrong address) is still a
clean `no_match`, even though it also carries one of those unresolved
clauses: the unknown clause can only turn an otherwise-matching rule into
`unknown`, never rescue a rule that has already failed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .flowtuple import FlowTuple
from .kleene import K_FALSE, K_TRUE, Kleene3, k_and, k_not
from .objects import (
    junos_address_match,
    junos_application_match,
    panos_address_match,
    panos_application_match,
    panos_service_match,
    pick_junos_address_book,
)

# Context key: ("zonepair", from_zone, to_zone) | ("global",) | ("panos",)
ContextKey = tuple


@dataclass(frozen=True)
class CompiledRule:
    rule_name: str
    action: str
    enabled: bool
    position: int
    provider: str
    context: ContextKey
    raw: dict[str, Any]
    object_book: dict[str, Any]

    def match(self, tuple_: FlowTuple) -> Kleene3:
        if self.provider == "juniper":
            return self._match_junos(tuple_)
        if self.provider == "paloalto":
            return self._match_panos(tuple_)
        raise ValueError(f"unsupported provider: {self.provider!r}")

    def _match_junos(self, t: FlowTuple) -> Kleene3:
        rule = self.raw
        from_zones = rule.get("from_zone") or ["any"]
        to_zones = rule.get("to_zone") or ["any"]
        zone_ok = ("any" in from_zones or t.ingress_zone in from_zones) and (
            "any" in to_zones or t.egress_zone in to_zones
        )
        if not zone_ok:
            return K_FALSE
        src_book = pick_junos_address_book(
            self.object_book.get("address_books", {}), t.ingress_zone
        )
        dst_book = pick_junos_address_book(self.object_book.get("address_books", {}), t.egress_zone)
        src = junos_address_match(
            rule.get("source_addresses", []), src_book, t.ingress_zone, t.src_ip
        )
        if rule.get("source_address_excluded"):
            src = k_not(src)
        dst = junos_address_match(rule.get("dest_addresses", []), dst_book, t.egress_zone, t.dst_ip)
        if rule.get("dest_address_excluded"):
            dst = k_not(dst)
        app = junos_application_match(
            rule.get("application", []), self.object_book, t.transport, t.dst_port
        )
        unknown_clause = Kleene3.UNKNOWN if rule.get("match_unknown") else K_TRUE
        return k_and(src, dst, app, unknown_clause)

    def _match_panos(self, t: FlowTuple) -> Kleene3:
        rule = self.raw
        from_zones = rule.get("from_zone") or ["any"]
        to_zones = rule.get("to_zone") or ["any"]
        zone_ok = ("any" in from_zones or t.ingress_zone in from_zones) and (
            "any" in to_zones or t.egress_zone in to_zones
        )
        if not zone_ok:
            return K_FALSE
        book = self.object_book
        src = panos_address_match(rule.get("source_addresses", []), book, t.src_ip)
        if rule.get("negate_source"):
            src = k_not(src)
        dst = panos_address_match(rule.get("dest_addresses", []), book, t.dst_ip)
        if rule.get("negate_destination"):
            dst = k_not(dst)
        service = panos_service_match(rule.get("service", []), book, t.transport, t.dst_port)
        application = panos_application_match(rule.get("application", []), t.app)
        unknown_clause = Kleene3.UNKNOWN if rule.get("match_unknown") else K_TRUE
        return k_and(src, dst, service, application, unknown_clause)


def _junos_context(rule: dict) -> ContextKey:
    if rule.get("is_global"):
        return ("global",)
    from_zones = rule.get("from_zone") or ["any"]
    to_zones = rule.get("to_zone") or ["any"]
    return ("zonepair", tuple(from_zones), tuple(to_zones))


def compile_rulebase(rules: list[dict], object_book: dict) -> list[CompiledRule]:
    """Compile a flat rule list (one device, one provider) into `CompiledRule`s,
    each tagged with its evaluation context. Order within the input list is
    preserved as `position` for the caller's context-grouped iteration --
    this function does not sort or renumber.
    """
    compiled = []
    for rule in rules:
        provider = rule["provider"]
        if provider == "juniper":
            context = _junos_context(rule)
        elif provider == "paloalto":
            context = ("panos",)
        else:
            raise ValueError(f"unsupported provider: {provider!r}")
        compiled.append(
            CompiledRule(
                rule_name=rule["rule_name"],
                action=rule.get("action", ""),
                enabled=bool(rule.get("enabled", True)),
                position=int(rule.get("position", 0)),
                provider=provider,
                context=context,
                raw=rule,
                object_book=object_book,
            )
        )
    return compiled


def context_order(provider: str) -> str:
    """Documents the context evaluation order per §1.2; `evaluator.firstmatch3`
    is the actual implementation. Junos: zone-pair context, then global, then
    default-deny. PAN-OS: one ordered list, then the implicit defaults."""
    return (
        "zonepair -> global -> default-deny"
        if provider == "juniper"
        else "ordered-list -> implicit-defaults"
    )
