"""Resolve address/service/application object references against task A's
collected object book (`ssdf_policy.collectors.{junos,panos}.collect_objects`
shape) into three-valued membership tests.

Every lookup here fails closed: a name missing from the book, a book entry
whose `kind` is `"unknown"`, or a self-referential/too-deep group all resolve
to `K_UNKNOWN` rather than being treated as "no restriction" or "no match".
"""

from __future__ import annotations

import ipaddress

from .kleene import K_FALSE, K_TRUE, K_UNKNOWN, Kleene3, k_or

_MAX_GROUP_DEPTH = 16
_ANY_NAMES = ("any", "")


def _is_any(name: str) -> bool:
    return name.strip().lower() in _ANY_NAMES


# ---------------------------------------------------------------------------
# Address resolution
# ---------------------------------------------------------------------------


def _ip_in_network(ip: ipaddress.IPv4Address, network_text: str) -> Kleene3:
    try:
        network = ipaddress.ip_network(network_text, strict=False)
    except ValueError:
        return K_UNKNOWN
    return K_TRUE if ip in network else K_FALSE


def _ip_in_range(ip: ipaddress.IPv4Address, low: str, high: str) -> Kleene3:
    try:
        lo = ipaddress.ip_address(low)
        hi = ipaddress.ip_address(high)
    except ValueError:
        return K_UNKNOWN
    return K_TRUE if lo <= ip <= hi else K_FALSE


def _ip_in_wildcard(ip: ipaddress.IPv4Address, value: str) -> Kleene3:
    """Junos `wildcard-address A.B.C.D/W.X.Y.Z`: mask bits set to 1 are
    "don't care" (the inverse of a netmask)."""
    try:
        base_text, mask_text = value.split("/", 1)
        base = int(ipaddress.ip_address(base_text))
        mask = int(ipaddress.ip_address(mask_text))
    except ValueError:
        return K_UNKNOWN
    ip_int = int(ip)
    care_bits = (~mask) & 0xFFFFFFFF
    return K_TRUE if (ip_int & care_bits) == (base & care_bits) else K_FALSE


def _resolve_junos_address_name(
    name: str, book: dict, ip: ipaddress.IPv4Address, depth: int
) -> Kleene3:
    if depth > _MAX_GROUP_DEPTH:
        return K_UNKNOWN
    if _is_any(name):
        return K_TRUE
    addresses = book.get("addresses", {})
    address_sets = book.get("address_sets", {})
    if name in addresses:
        entry = addresses[name]
        kind = entry.get("kind")
        if kind == "address":
            return _ip_in_network(ip, entry.get("value", ""))
        if kind == "range":
            return _ip_in_range(ip, entry.get("low", ""), entry.get("high", ""))
        if kind == "wildcard":
            return _ip_in_wildcard(ip, entry.get("value", ""))
        return K_UNKNOWN  # dns-name, unparsed, or any future unknown kind
    if name in address_sets:
        members = address_sets[name].get("members", [])
        return k_or(*(_resolve_junos_address_name(m, book, ip, depth + 1) for m in members))
    return K_UNKNOWN  # referenced but not present in the collected book


def junos_address_match(names: list[str], book: dict, zone: str, ip_text: str | None) -> Kleene3:
    """Match an IP against a Junos rule's source/destination address list.

    `book` is one `address_books[...]` entry (the book attached to `zone`, or
    the `"global"` book). An empty `names` list (match omitted entirely) means
    "any", matching the collector's own convention for a bare `match
    source-address`/`destination-address` clause never appearing.
    """
    if not names:
        return K_TRUE
    if ip_text is None:
        return K_UNKNOWN
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError:
        return K_UNKNOWN
    if not isinstance(ip, ipaddress.IPv4Address):
        return K_UNKNOWN  # IPv6 is out of scope for v1 (doc §3)
    return k_or(*(_resolve_junos_address_name(n, book, ip, 0) for n in names))


def pick_junos_address_book(address_books: dict, zone: str) -> dict:
    """Pick the address book a zone's rules resolve names against: the book
    explicitly attached to this zone, else the book literally named for the
    zone (`zone:<zone>` legacy form), else the global book.
    """
    for book in address_books.values():
        if zone in book.get("attached_zones", []):
            return book
    if f"zone:{zone}" in address_books:
        return address_books[f"zone:{zone}"]
    return address_books.get("global", {"addresses": {}, "address_sets": {}})


def _resolve_panos_address_name(
    name: str, addresses: dict, address_groups: dict, ip: ipaddress.IPv4Address, depth: int
) -> Kleene3:
    if depth > _MAX_GROUP_DEPTH:
        return K_UNKNOWN
    if _is_any(name):
        return K_TRUE
    if name in addresses:
        entry = addresses[name]
        kind = entry.get("kind")
        value = entry.get("value", "")
        if kind == "ip-netmask":
            return _ip_in_network(ip, value)
        if kind == "ip-range":
            if "-" in value:
                low, high = value.split("-", 1)
                return _ip_in_range(ip, low.strip(), high.strip())
            return K_UNKNOWN
        if kind == "ip-wildcard":
            return _ip_in_wildcard(ip, value)
        return K_UNKNOWN  # fqdn or unrecognized-address-type
    if name in address_groups:
        entry = address_groups[name]
        if entry.get("kind") == "unknown":
            return K_UNKNOWN  # dynamic address group
        members = entry.get("members", [])
        return k_or(
            *(
                _resolve_panos_address_name(m, addresses, address_groups, ip, depth + 1)
                for m in members
            )
        )
    return K_UNKNOWN


def panos_address_match(names: list[str], book: dict, ip_text: str | None) -> Kleene3:
    if not names or names == ["any"]:
        return K_TRUE
    if ip_text is None:
        return K_UNKNOWN
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError:
        return K_UNKNOWN
    if not isinstance(ip, ipaddress.IPv4Address):
        return K_UNKNOWN
    addresses = book.get("addresses", {})
    address_groups = book.get("address_groups", {})
    return k_or(*(_resolve_panos_address_name(n, addresses, address_groups, ip, 0) for n in names))


# ---------------------------------------------------------------------------
# Service / application resolution
# ---------------------------------------------------------------------------


def _parse_port_spec(value: str) -> tuple[int, int] | None:
    value = (value or "").strip()
    if not value:
        return None
    if "-" in value:
        lo_text, hi_text = value.split("-", 1)
    else:
        lo_text = hi_text = value
    try:
        lo, hi = int(lo_text), int(hi_text)
    except ValueError:
        return None
    return (lo, hi) if lo <= hi else (hi, lo)


def _port_matches(entry_value: str, port: int | None) -> Kleene3:
    if not entry_value:
        return K_TRUE  # no port restriction recorded for this application/service
    if port is None:
        return K_UNKNOWN
    parsed = _parse_port_spec(entry_value)
    if parsed is None:
        return K_UNKNOWN
    lo, hi = parsed
    return K_TRUE if lo <= port <= hi else K_FALSE


def _resolve_junos_application_name(
    name: str,
    applications: dict,
    application_sets: dict,
    predefined_applications: dict,
    predefined_application_sets: dict,
    transport: str | None,
    port: int | None,
    depth: int,
) -> Kleene3:
    if depth > _MAX_GROUP_DEPTH:
        return K_UNKNOWN
    if _is_any(name):
        return K_TRUE
    entry = applications.get(name) or predefined_applications.get(name)
    if entry is not None:
        if entry.get("kind") != "application":
            return K_UNKNOWN  # multi-term / unrecognized-field, flagged at collection
        protocol = (entry.get("protocol") or "").lower()
        if protocol:
            if transport is None:
                return K_UNKNOWN
            if protocol != transport.lower():
                return K_FALSE
        return _port_matches(entry.get("destination_port", ""), port)
    members = None
    for container in (application_sets, predefined_application_sets):
        if name in container:
            members = container[name].get("members", [])
            break
    if members is not None:
        return k_or(
            *(
                _resolve_junos_application_name(
                    m,
                    applications,
                    application_sets,
                    predefined_applications,
                    predefined_application_sets,
                    transport,
                    port,
                    depth + 1,
                )
                for m in members
            )
        )
    return K_UNKNOWN


def junos_application_match(
    names: list[str], object_book: dict, transport: str | None, port: int | None
) -> Kleene3:
    if not names:
        return K_TRUE
    return k_or(
        *(
            _resolve_junos_application_name(
                n,
                object_book.get("applications", {}),
                object_book.get("application_sets", {}),
                object_book.get("predefined_applications", {}),
                object_book.get("predefined_application_sets", {}),
                transport,
                port,
                0,
            )
            for n in names
        )
    )


def _resolve_panos_service_name(
    name: str,
    services: dict,
    service_groups: dict,
    transport: str | None,
    port: int | None,
    depth: int,
) -> Kleene3:
    if depth > _MAX_GROUP_DEPTH:
        return K_UNKNOWN
    if _is_any(name):
        return K_TRUE
    if name.lower() == "application-default":
        # Needs the App-ID content DB's per-application standard ports (doc §1.2).
        return K_UNKNOWN
    if name in services:
        entry = services[name]
        if entry.get("kind") == "unknown":
            return K_UNKNOWN
        protocol = (entry.get("protocol") or "").lower()
        if protocol:
            if transport is None:
                return K_UNKNOWN
            if protocol != transport.lower():
                return K_FALSE
        return _port_matches(entry.get("port", ""), port)
    if name in service_groups:
        members = service_groups[name].get("members", [])
        return k_or(
            *(
                _resolve_panos_service_name(m, services, service_groups, transport, port, depth + 1)
                for m in members
            )
        )
    return K_UNKNOWN


def panos_service_match(
    names: list[str], object_book: dict, transport: str | None, port: int | None
) -> Kleene3:
    if not names or names == ["any"]:
        return K_TRUE
    services = object_book.get("services", {})
    service_groups = object_book.get("service_groups", {})
    return k_or(
        *(
            _resolve_panos_service_name(n, services, service_groups, transport, port, 0)
            for n in names
        )
    )


def panos_application_match(names: list[str], logged_app: str | None) -> Kleene3:
    """PAN-OS named application/application-group list vs. the logged post-App-ID
    app name.

    Task A did not collect a PAN-OS application/application-group object book
    (only address/address-group/service/service-group/schedule -- see
    `collectors/panos.py::collect_objects`), so a named entry that is actually
    a group can't be expanded here. This is intentionally MORE conservative
    than the change-impact-scope doc's own v1-unknown list (which only calls
    out App-ID filters and `application-default`): any non-wildcard
    application reference is reported `unknown` rather than guessed via a
    literal-name compare that would silently misclassify a group reference.
    Call this out to reviewers explicitly; resolved once a PAN-OS application
    object book exists.
    """
    if not names or names == ["any"]:
        return K_TRUE
    return K_UNKNOWN
