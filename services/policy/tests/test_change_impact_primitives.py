"""Kleene3 logic, object-book resolution, and effective-tuple extraction --
the primitives the evaluator's match clauses are built from (doc §1.2/§1.3).
"""

from ssdf_policy.change_impact.flowtuple import effective_tuple
from ssdf_policy.change_impact.kleene import K_FALSE, K_TRUE, K_UNKNOWN, k_and, k_not, k_or
from ssdf_policy.change_impact.objects import (
    junos_address_match,
    junos_application_match,
    panos_address_match,
    panos_application_match,
    panos_service_match,
)


# ---------------------------------------------------------------------------
# Kleene3
# ---------------------------------------------------------------------------


def test_kleene_and_false_dominates_unknown():
    assert k_and(K_FALSE, K_UNKNOWN) is K_FALSE
    assert k_and(K_TRUE, K_UNKNOWN) is K_UNKNOWN
    assert k_and(K_TRUE, K_TRUE) is K_TRUE
    assert k_and() is K_TRUE


def test_kleene_or_true_dominates_unknown():
    assert k_or(K_TRUE, K_UNKNOWN) is K_TRUE
    assert k_or(K_FALSE, K_UNKNOWN) is K_UNKNOWN
    assert k_or(K_FALSE, K_FALSE) is K_FALSE
    assert k_or() is K_FALSE


def test_kleene_not():
    assert k_not(K_TRUE) is K_FALSE
    assert k_not(K_FALSE) is K_TRUE
    assert k_not(K_UNKNOWN) is K_UNKNOWN


# ---------------------------------------------------------------------------
# Junos address resolution
# ---------------------------------------------------------------------------

JUNOS_BOOK = {
    "addresses": {
        "WEB1": {"kind": "address", "value": "10.1.1.0/24"},
        "DNSNAME": {"kind": "unknown", "reason": "dns-name"},
        "RANGE1": {"kind": "range", "low": "10.3.0.1", "high": "10.3.0.10"},
        "WILD1": {"kind": "wildcard", "value": "10.4.0.0/0.0.255.0"},
    },
    "address_sets": {
        "SET1": {"members": ["WEB1", "RANGE1"]},
        "NESTED": {"members": ["SET1"]},
    },
    "attached_zones": ["trust"],
}


def test_junos_address_match_plain_network():
    assert junos_address_match(["WEB1"], JUNOS_BOOK, "trust", "10.1.1.5") is K_TRUE
    assert junos_address_match(["WEB1"], JUNOS_BOOK, "trust", "10.9.9.9") is K_FALSE


def test_junos_address_match_empty_list_is_any():
    assert junos_address_match([], JUNOS_BOOK, "trust", "10.9.9.9") is K_TRUE


def test_junos_address_match_dns_name_is_unknown():
    assert junos_address_match(["DNSNAME"], JUNOS_BOOK, "trust", "10.1.1.5") is K_UNKNOWN


def test_junos_address_match_range():
    assert junos_address_match(["RANGE1"], JUNOS_BOOK, "trust", "10.3.0.5") is K_TRUE
    assert junos_address_match(["RANGE1"], JUNOS_BOOK, "trust", "10.3.0.99") is K_FALSE


def test_junos_address_match_wildcard():
    # mask 0.0.255.0 means the third octet is "don't care"
    assert junos_address_match(["WILD1"], JUNOS_BOOK, "trust", "10.4.99.0") is K_TRUE
    assert junos_address_match(["WILD1"], JUNOS_BOOK, "trust", "10.4.99.1") is K_FALSE


def test_junos_address_match_nested_set_resolves_recursively():
    assert junos_address_match(["NESTED"], JUNOS_BOOK, "trust", "10.1.1.5") is K_TRUE
    assert junos_address_match(["NESTED"], JUNOS_BOOK, "trust", "10.3.0.5") is K_TRUE
    assert junos_address_match(["NESTED"], JUNOS_BOOK, "trust", "172.16.0.1") is K_FALSE


def test_junos_address_match_unresolvable_reference_is_unknown():
    assert junos_address_match(["GHOST"], JUNOS_BOOK, "trust", "10.1.1.5") is K_UNKNOWN


def test_junos_address_match_ipv6_is_unknown():
    assert junos_address_match(["WEB1"], JUNOS_BOOK, "trust", "2001:db8::1") is K_UNKNOWN


# ---------------------------------------------------------------------------
# Junos application resolution
# ---------------------------------------------------------------------------

JUNOS_APP_BOOK = {
    "applications": {
        "CUSTOM-APP": {"kind": "application", "protocol": "tcp", "destination_port": "8443"},
        "MULTI-TERM": {"kind": "unknown", "reason": "multi-term"},
    },
    "application_sets": {"APP-SET": {"members": ["CUSTOM-APP"]}},
    "predefined_applications": {
        "junos-http": {"kind": "application", "protocol": "tcp", "destination_port": "80"},
    },
    "predefined_application_sets": {},
}


def test_junos_application_match_protocol_and_port():
    assert junos_application_match(["CUSTOM-APP"], JUNOS_APP_BOOK, "tcp", 8443) is K_TRUE
    assert junos_application_match(["CUSTOM-APP"], JUNOS_APP_BOOK, "tcp", 443) is K_FALSE
    assert junos_application_match(["CUSTOM-APP"], JUNOS_APP_BOOK, "udp", 8443) is K_FALSE


def test_junos_application_match_predefined():
    assert junos_application_match(["junos-http"], JUNOS_APP_BOOK, "tcp", 80) is K_TRUE


def test_junos_application_match_multi_term_is_unknown():
    assert junos_application_match(["MULTI-TERM"], JUNOS_APP_BOOK, "tcp", 80) is K_UNKNOWN


def test_junos_application_match_set_resolves_members():
    assert junos_application_match(["APP-SET"], JUNOS_APP_BOOK, "tcp", 8443) is K_TRUE


def test_junos_application_match_any_is_wildcard():
    assert junos_application_match(["any"], JUNOS_APP_BOOK, "udp", 9999) is K_TRUE


# ---------------------------------------------------------------------------
# PAN-OS resolution
# ---------------------------------------------------------------------------

PANOS_BOOK = {
    "addresses": {
        "SRV1": {"kind": "ip-netmask", "value": "192.168.1.0/24"},
        "RANGE1": {"kind": "ip-range", "value": "192.168.2.1-192.168.2.10"},
        "FQDN1": {"kind": "unknown", "reason": "fqdn"},
    },
    "address_groups": {
        "GRP1": {"kind": "static", "members": ["SRV1"]},
        "DAG1": {"kind": "unknown", "reason": "dynamic-address-group"},
    },
    "services": {
        "SVC-HTTPS": {"protocol": "tcp", "port": "443", "source_port": ""},
    },
    "service_groups": {"SVC-GRP": {"members": ["SVC-HTTPS"]}},
}


def test_panos_address_match_netmask_and_range():
    assert panos_address_match(["SRV1"], PANOS_BOOK, "192.168.1.5") is K_TRUE
    assert panos_address_match(["SRV1"], PANOS_BOOK, "10.0.0.1") is K_FALSE
    assert panos_address_match(["RANGE1"], PANOS_BOOK, "192.168.2.5") is K_TRUE


def test_panos_address_match_fqdn_is_unknown():
    assert panos_address_match(["FQDN1"], PANOS_BOOK, "192.168.1.5") is K_UNKNOWN


def test_panos_address_match_dynamic_group_is_unknown():
    assert panos_address_match(["DAG1"], PANOS_BOOK, "192.168.1.5") is K_UNKNOWN


def test_panos_address_match_static_group_resolves():
    assert panos_address_match(["GRP1"], PANOS_BOOK, "192.168.1.5") is K_TRUE


def test_panos_service_match():
    assert panos_service_match(["SVC-HTTPS"], PANOS_BOOK, "tcp", 443) is K_TRUE
    assert panos_service_match(["SVC-HTTPS"], PANOS_BOOK, "tcp", 80) is K_FALSE
    assert panos_service_match(["SVC-GRP"], PANOS_BOOK, "tcp", 443) is K_TRUE


def test_panos_service_application_default_is_unknown():
    assert panos_service_match(["application-default"], PANOS_BOOK, "tcp", 443) is K_UNKNOWN


def test_panos_application_match_named_group_is_unknown_in_v1():
    # No PAN-OS application/application-group object book exists upstream
    # (task A only collected address/service objects) -- see objects.py
    # docstring. Deliberately MORE conservative than the doc's own v1-unknown
    # list rather than risk a literal-name false match against a group.
    assert panos_application_match(["ssl"], "ssl") is K_UNKNOWN
    assert panos_application_match([], "ssl") is K_TRUE
    assert panos_application_match(["any"], "ssl") is K_TRUE


# ---------------------------------------------------------------------------
# Effective-tuple extraction (doc §1.3)
# ---------------------------------------------------------------------------


def test_junos_effective_tuple_prefers_nat_destination():
    row = {
        "observer_ingress_zone": "trust",
        "observer_egress_zone": "untrust",
        "source_ip": "10.1.1.5",
        "destination_ip": "203.0.113.9",
        "network_transport": "tcp",
        "destination_port": "443",
        "ext": {"nat-destination-address": "10.9.9.9"},
    }
    tup = effective_tuple(row, "juniper")
    assert tup.dst_ip == "10.9.9.9"
    assert tup.src_ip == "10.1.1.5"  # SNAT happens after policy -> pre-NAT src used
    assert tup.dst_port == 443


def test_junos_effective_tuple_falls_back_without_dnat():
    row = {
        "observer_ingress_zone": "trust",
        "observer_egress_zone": "untrust",
        "source_ip": "10.1.1.5",
        "destination_ip": "203.0.113.9",
        "network_transport": "tcp",
        "destination_port": "443",
        "ext": {"nat-destination-address": "0.0.0.0"},
    }
    tup = effective_tuple(row, "juniper")
    assert tup.dst_ip == "203.0.113.9"


def test_panos_effective_tuple_uses_pre_nat_ips_and_logged_app():
    row = {
        "observer_ingress_zone": "trust",
        "observer_egress_zone": "untrust",
        "source_ip": "10.1.1.5",
        "destination_ip": "203.0.113.9",
        "network_transport": "tcp",
        "destination_port": "443",
        "ext": {"panw.panos.application": "ssl"},
    }
    tup = effective_tuple(row, "paloalto")
    assert tup.dst_ip == "203.0.113.9"  # pre-NAT, no DNAT substitution for PAN-OS
    assert tup.app == "ssl"
