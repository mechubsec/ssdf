"""MEC-992: Junos address-book + application object-book collection."""

from ssdf_policy.collectors.junos import (
    parse_address_book,
    parse_applications,
    parse_predefined_applications,
)

ADDRESS_BOOK_TEXT = """
set security address-book global address ADDR1 10.1.1.0/24
set security address-book global address ADDR2 dns-name example.com
set security address-book global address ADDR3 range-address 10.3.0.1 to 10.3.0.10
set security address-book global address ADDR4 wildcard-address 10.4.0.0/255.0.255.0
set security address-book global address-set SET1 address ADDR1
set security address-book global address-set SET1 address ADDR3
set security address-book global address-set NESTED address-set SET1
""".strip()

ZONE_ADDRESS_BOOK_TEXT = """
set security zones security-zone trust address-book address ZADDR1 10.2.0.0/16
set security zones security-zone trust address-book address-set ZSET1 address ZADDR1
""".strip()

APPLICATIONS_TEXT = """
set applications application CUSTOM-APP protocol tcp
set applications application CUSTOM-APP destination-port 8443
set applications application-set CUSTOM-SET application CUSTOM-APP
""".strip()

PREDEFINED_TEXT = """
set groups junos-defaults applications application junos-http protocol tcp
set groups junos-defaults applications application junos-http destination-port 80
set groups junos-defaults applications application junos-http inactivity-timeout 300
set groups junos-defaults applications application-set junos-cifs application junos-netbios-session
""".strip()


def test_plain_address_resolves_to_value():
    books = parse_address_book(ADDRESS_BOOK_TEXT)
    assert books["global"]["addresses"]["ADDR1"] == {"kind": "address", "value": "10.1.1.0/24"}


def test_dns_name_address_resolves_to_unknown():
    books = parse_address_book(ADDRESS_BOOK_TEXT)
    assert books["global"]["addresses"]["ADDR2"] == {"kind": "unknown", "reason": "dns-name"}


def test_range_address_resolves_to_low_high():
    books = parse_address_book(ADDRESS_BOOK_TEXT)
    assert books["global"]["addresses"]["ADDR3"] == {
        "kind": "range",
        "low": "10.3.0.1",
        "high": "10.3.0.10",
    }


def test_wildcard_address_resolves_to_value():
    books = parse_address_book(ADDRESS_BOOK_TEXT)
    assert books["global"]["addresses"]["ADDR4"] == {
        "kind": "wildcard",
        "value": "10.4.0.0/255.0.255.0",
    }


def test_address_set_collects_members_including_nested_sets():
    books = parse_address_book(ADDRESS_BOOK_TEXT)
    assert set(books["global"]["address_sets"]["SET1"]["members"]) == {"ADDR1", "ADDR3"}
    assert books["global"]["address_sets"]["NESTED"]["members"] == ["SET1"]


def test_zone_address_book_is_keyed_separately_from_global():
    books = parse_address_book(ZONE_ADDRESS_BOOK_TEXT)
    assert books["zone:trust"]["addresses"]["ZADDR1"] == {"kind": "address", "value": "10.2.0.0/16"}
    assert books["zone:trust"]["address_sets"]["ZSET1"]["members"] == ["ZADDR1"]


def test_custom_application_fields_are_parsed():
    result = parse_applications(APPLICATIONS_TEXT)
    assert result["applications"]["CUSTOM-APP"]["protocol"] == "tcp"
    assert result["applications"]["CUSTOM-APP"]["destination_port"] == "8443"
    assert result["application_sets"]["CUSTOM-SET"]["members"] == ["CUSTOM-APP"]


def test_predefined_applications_parsed_from_junos_defaults_group():
    # Confirmed read-only-readable on vsrx-ci, 2026-09-30 (task MEC-992 item 5):
    # `show configuration groups junos-defaults applications | display set`.
    predefined = parse_predefined_applications(PREDEFINED_TEXT)
    assert predefined["applications"]["junos-http"]["protocol"] == "tcp"
    assert predefined["applications"]["junos-http"]["destination_port"] == "80"
    assert predefined["applications"]["junos-http"]["inactivity_timeout"] == "300"


def test_predefined_application_sets_are_kept_not_discarded():
    # MEC-992 review (F2): a rule matching `junos-cifs` could not be resolved
    # if the predefined application-set were parsed and then thrown away.
    text = (
        "set groups junos-defaults applications application-set junos-cifs "
        "application junos-netbios-session"
    )
    predefined = parse_predefined_applications(text)
    assert predefined["application_sets"]["junos-cifs"]["members"] == ["junos-netbios-session"]


def test_term_based_application_resolves_to_unknown_not_empty():
    # MEC-992 review (F1): reading only tokens[2] silently dropped every term's
    # protocol/port, so a term-based application resolved to `{}` and the
    # evaluator would read it as "any".
    text = (
        "set applications application MSRPC term t1 protocol tcp\n"
        "set applications application MSRPC term t1 destination-port 135\n"
        "set applications application MSRPC term t1 uuid 12345678-1234-1234-1234-123456789abc\n"
    )
    result = parse_applications(text)
    assert result["applications"]["MSRPC"] == {"kind": "unknown", "reason": "multi-term"}


def test_application_field_outside_allowlist_resolves_to_unknown():
    text = "set applications application ICMP-APP icmp-type 8"
    result = parse_applications(text)
    assert result["applications"]["ICMP-APP"] == {"kind": "unknown", "reason": "unrecognized-field"}


def test_address_description_does_not_overwrite_address_value():
    # MEC-992 review (F6): the `else` branch used to treat any unrecognized
    # keyword as the IP value, so a `description` line appearing after the
    # address line silently replaced A1's value with the word "description".
    text = (
        "set security address-book global address A1 10.1.1.0/24\n"
        "set security address-book global address A1 description web\n"
    )
    books = parse_address_book(text)
    assert books["global"]["addresses"]["A1"] == {"kind": "address", "value": "10.1.1.0/24"}


def test_unparseable_address_value_resolves_to_unknown():
    text = "set security address-book global address A1 not-an-ip\n"
    books = parse_address_book(text)
    assert books["global"]["addresses"]["A1"] == {"kind": "unknown", "reason": "unparsed"}


def test_address_book_attach_zone_is_recorded():
    # MEC-992 review (F7): without the attachment, two books that both define
    # the same address name are ambiguous for a rule scoped to `dmz`.
    text = (
        "set security address-book BOOK1 address A1 10.1.1.0/24\n"
        "set security address-book BOOK1 attach zone dmz\n"
    )
    books = parse_address_book(text)
    assert books["BOOK1"]["attached_zones"] == ["dmz"]


def test_empty_input_yields_empty_book():
    assert parse_address_book("") == {}
    result = parse_applications("")
    assert result == {"applications": {}, "application_sets": {}}


def test_collect_objects_builds_per_device_object_book():
    from ssdf_policy.collectors.junos import JunosPolicyCollector

    class _FakeClient:
        def call_tool(self, name, args=None):
            command = (args or {}).get("command", "")
            if "address-book" in command:
                return ADDRESS_BOOK_TEXT
            if "security zones" in command:
                return ZONE_ADDRESS_BOOK_TEXT
            if "groups junos-defaults" in command:
                return PREDEFINED_TEXT
            if "applications" in command:
                return APPLICATIONS_TEXT
            return ""

    books = JunosPolicyCollector(["vSRX-test10"]).collect_objects(
        _FakeClient(), "2026-09-30T00:00:00Z"
    )
    assert len(books) == 1
    book = books[0]
    assert book["provider"] == "juniper"
    assert book["device_name"] == "vSRX-test10"
    assert book["object_book"]["address_books"]["global"]["addresses"]["ADDR1"]["kind"] == "address"
    assert book["object_book"]["applications"]["CUSTOM-APP"]["protocol"] == "tcp"
    assert book["object_book"]["predefined_applications"]["junos-http"]["protocol"] == "tcp"
    assert book["object_book"]["predefined_application_sets"]["junos-cifs"]["members"] == [
        "junos-netbios-session"
    ]


def test_collect_objects_skips_unreachable_device():
    from ssdf_policy.collectors.junos import JunosPolicyCollector

    class _BoomClient:
        def call_tool(self, name, args=None):
            raise RuntimeError("device unreachable")

    books = JunosPolicyCollector(["vSRX-test10"]).collect_objects(
        _BoomClient(), "2026-09-30T00:00:00Z"
    )
    assert books == []
