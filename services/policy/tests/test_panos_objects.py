"""MEC-992: PAN-OS address/service object-book collection (static only; DAG/EDL
out of scope and resolve to unknown)."""

from ssdf_policy.collectors.panos import (
    parse_address_groups,
    parse_address_objects,
    parse_schedules,
    parse_security_rules,
    parse_service_groups,
    parse_service_objects,
)

ADDRESS_XML = (
    "<address>"
    "<entry name='ADDR1'><ip-netmask>10.1.1.0/24</ip-netmask></entry>"
    "<entry name='ADDR2'><ip-range>10.1.1.1-10.1.1.10</ip-range></entry>"
    "<entry name='ADDR3'><fqdn>example.com</fqdn></entry>"
    "</address>"
)

ADDRESS_GROUP_XML = (
    "<address-group>"
    "<entry name='GRP-STATIC'><static><member>ADDR1</member><member>ADDR2</member></static></entry>"
    "<entry name='GRP-DYNAMIC'><dynamic><filter>tag.quarantine</filter></dynamic></entry>"
    "</address-group>"
)

SERVICE_XML = (
    "<service>"
    "<entry name='SVC-TCP'><protocol><tcp><port>8443</port></tcp></protocol></entry>"
    "<entry name='SVC-UDP'><protocol><udp><port>53</port></udp></protocol></entry>"
    "</service>"
)

SERVICE_GROUP_XML = (
    "<service-group>"
    "<entry name='SGRP1'><members><member>SVC-TCP</member><member>SVC-UDP</member></members></entry>"
    "</service-group>"
)

SCHEDULE_XML = "<schedule><entry name='BUSINESS-HOURS'></entry></schedule>"


def test_ip_netmask_address_resolves_to_value():
    objects = parse_address_objects(ADDRESS_XML)
    assert objects["ADDR1"] == {"kind": "ip-netmask", "value": "10.1.1.0/24"}


def test_ip_range_address_resolves_to_value():
    objects = parse_address_objects(ADDRESS_XML)
    assert objects["ADDR2"] == {"kind": "ip-range", "value": "10.1.1.1-10.1.1.10"}


def test_fqdn_address_resolves_to_unknown():
    objects = parse_address_objects(ADDRESS_XML)
    assert objects["ADDR3"] == {"kind": "unknown", "reason": "fqdn"}


def test_static_address_group_collects_members():
    groups = parse_address_groups(ADDRESS_GROUP_XML)
    assert groups["GRP-STATIC"] == {"kind": "static", "members": ["ADDR1", "ADDR2"]}


def test_dynamic_address_group_resolves_to_unknown():
    groups = parse_address_groups(ADDRESS_GROUP_XML)
    assert groups["GRP-DYNAMIC"] == {"kind": "unknown", "reason": "dynamic-address-group"}


def test_service_objects_capture_protocol_and_port():
    services = parse_service_objects(SERVICE_XML)
    assert services["SVC-TCP"]["protocol"] == "tcp"
    assert services["SVC-TCP"]["port"] == "8443"
    assert services["SVC-UDP"]["protocol"] == "udp"
    assert services["SVC-UDP"]["port"] == "53"


def test_service_group_collects_members():
    groups = parse_service_groups(SERVICE_GROUP_XML)
    assert groups["SGRP1"]["members"] == ["SVC-TCP", "SVC-UDP"]


def test_schedules_are_captured_by_name():
    schedules = parse_schedules(SCHEDULE_XML)
    assert "BUSINESS-HOURS" in schedules


def test_negate_and_schedule_are_parsed_on_rules():
    text = (
        "<rules><entry name='r1' uuid='u-1'>"
        "<from><member>trust</member></from><to><member>untrust</member></to>"
        "<source><member>10.0.0.0/8</member></source>"
        "<destination><member>any</member></destination>"
        "<application><member>any</member></application>"
        "<service><member>any</member></service>"
        "<action>allow</action>"
        "<negate-source>yes</negate-source>"
        "<schedule>BUSINESS-HOURS</schedule>"
        "</entry></rules>"
    )
    rules = parse_security_rules(text, "panosvm", "2026-09-30T00:00:00")
    assert rules[0]["negate_source"] is True
    assert rules[0]["negate_destination"] is False
    assert rules[0]["schedule"] == "BUSINESS-HOURS"


def test_rule_with_schedule_flags_match_unknown():
    # MEC-992 review (F5): a schedule binding is recorded but not evaluated by
    # this collector, so a rule scoped to it must not read as always-active.
    text = (
        "<rules><entry name='r1'>"
        "<from><member>trust</member></from><to><member>untrust</member></to>"
        "<source><member>any</member></source>"
        "<destination><member>any</member></destination>"
        "<application><member>any</member></application>"
        "<service><member>any</member></service>"
        "<action>allow</action>"
        "<schedule>BIZ</schedule>"
        "</entry></rules>"
    )
    rules = parse_security_rules(text, "panosvm", "2026-09-30T00:00:00")
    assert rules[0]["match_unknown"] is True


def test_rule_with_source_user_and_category_flags_match_unknown():
    text = (
        "<rules><entry name='r1'>"
        "<from><member>trust</member></from><to><member>untrust</member></to>"
        "<source><member>any</member></source>"
        "<destination><member>any</member></destination>"
        "<application><member>any</member></application>"
        "<service><member>any</member></service>"
        "<action>allow</action>"
        "<source-user><member>corp\\alice</member></source-user>"
        "<category><member>gambling</member></category>"
        "</entry></rules>"
    )
    rules = parse_security_rules(text, "panosvm", "2026-09-30T00:00:00")
    assert rules[0]["source_user"] == ["corp\\alice"]
    assert rules[0]["url_category"] == ["gambling"]
    assert rules[0]["match_unknown"] is True


def test_rule_with_only_any_members_is_not_flagged_unknown():
    text = (
        "<rules><entry name='r1'>"
        "<from><member>trust</member></from><to><member>untrust</member></to>"
        "<source><member>any</member></source>"
        "<destination><member>any</member></destination>"
        "<application><member>any</member></application>"
        "<service><member>any</member></service>"
        "<action>allow</action>"
        "<source-user><member>any</member></source-user>"
        "<category><member>any</member></category>"
        "</entry></rules>"
    )
    rules = parse_security_rules(text, "panosvm", "2026-09-30T00:00:00")
    assert rules[0]["match_unknown"] is False


def test_empty_input_yields_empty_objects():
    assert parse_address_objects("") == {}
    assert parse_address_groups("") == {}
    assert parse_service_objects("") == {}
    assert parse_service_groups("") == {}
    assert parse_schedules("") == {}


def test_collect_objects_builds_object_book_from_all_xpaths():
    from ssdf_policy.collectors.panos import PanosPolicyCollector

    class _FakeClient:
        def call_tool(self, name, args=None):
            xpath = (args or {}).get("xpath", "")
            if xpath.endswith("/address-group"):
                return ADDRESS_GROUP_XML
            if xpath.endswith("/address"):
                return ADDRESS_XML
            if xpath.endswith("/service-group"):
                return SERVICE_GROUP_XML
            if xpath.endswith("/service"):
                return SERVICE_XML
            if xpath.endswith("/schedule"):
                return SCHEDULE_XML
            raise AssertionError(f"unexpected xpath {xpath}")

    books = PanosPolicyCollector("panosvm").collect_objects(_FakeClient(), "2026-09-30T00:00:00Z")
    assert len(books) == 1
    book = books[0]
    assert book["provider"] == "paloalto"
    assert book["device_name"] == "panosvm"
    assert book["object_book"]["addresses"]["ADDR1"]["kind"] == "ip-netmask"
    assert book["object_book"]["address_groups"]["GRP-STATIC"]["kind"] == "static"
    assert book["object_book"]["services"]["SVC-TCP"]["protocol"] == "tcp"
    assert book["object_book"]["service_groups"]["SGRP1"]["members"] == ["SVC-TCP", "SVC-UDP"]
    assert "BUSINESS-HOURS" in book["object_book"]["schedules"]


def test_collect_objects_truncated_type_aborts_whole_object_book():
    # MEC-992 review (F4): a truncated fetch for ONE object type used to be
    # recorded as `{}` for that type while the other four types were still
    # emitted -- indistinguishable from a legitimately empty container, and
    # ssdf.object_book_hash would record it as a real content change. A
    # transient truncation must refuse the whole pass instead.
    from ssdf_policy.collectors.panos import PanosPolicyCollector

    class _TruncatingClient:
        def call_tool(self, name, args=None):
            xpath = (args or {}).get("xpath", "")
            if xpath.endswith("/address"):
                return '{"truncated": true}'
            if xpath.endswith("/address-group"):
                return ADDRESS_GROUP_XML
            if xpath.endswith("/service-group"):
                return SERVICE_GROUP_XML
            if xpath.endswith("/service"):
                return SERVICE_XML
            if xpath.endswith("/schedule"):
                return SCHEDULE_XML
            raise AssertionError(f"unexpected xpath {xpath}")

    books = PanosPolicyCollector("panosvm").collect_objects(
        _TruncatingClient(), "2026-09-30T00:00:00Z"
    )
    assert books == []


def test_collect_objects_unparseable_type_aborts_whole_object_book():
    from ssdf_policy.collectors.panos import PanosPolicyCollector

    class _UnparseableClient:
        def call_tool(self, name, args=None):
            xpath = (args or {}).get("xpath", "")
            if xpath.endswith("/address"):
                return "not xml at all <<<"
            if xpath.endswith("/address-group"):
                return ADDRESS_GROUP_XML
            if xpath.endswith("/service-group"):
                return SERVICE_GROUP_XML
            if xpath.endswith("/service"):
                return SERVICE_XML
            if xpath.endswith("/schedule"):
                return SCHEDULE_XML
            raise AssertionError(f"unexpected xpath {xpath}")

    books = PanosPolicyCollector("panosvm").collect_objects(
        _UnparseableClient(), "2026-09-30T00:00:00Z"
    )
    assert books == []


def test_collect_objects_fetch_failure_aborts_whole_object_book():
    from ssdf_policy.collectors.panos import PanosPolicyCollector

    class _BoomClient:
        def call_tool(self, name, args=None):
            xpath = (args or {}).get("xpath", "")
            if xpath.endswith("/address"):
                raise TimeoutError("device unreachable")
            if xpath.endswith("/address-group"):
                return ADDRESS_GROUP_XML
            if xpath.endswith("/service-group"):
                return SERVICE_GROUP_XML
            if xpath.endswith("/service"):
                return SERVICE_XML
            if xpath.endswith("/schedule"):
                return SCHEDULE_XML
            raise AssertionError(f"unexpected xpath {xpath}")

    books = PanosPolicyCollector("panosvm").collect_objects(_BoomClient(), "2026-09-30T00:00:00Z")
    assert books == []


def test_collect_objects_genuinely_empty_container_is_not_a_failure():
    # An empty-but-valid container must still resolve to `{}` for that key,
    # not be misclassified as a parse failure.
    from ssdf_policy.collectors.panos import PanosPolicyCollector

    class _EmptyAddressClient:
        def call_tool(self, name, args=None):
            xpath = (args or {}).get("xpath", "")
            if xpath.endswith("/address"):
                return "<address/>"
            if xpath.endswith("/address-group"):
                return ADDRESS_GROUP_XML
            if xpath.endswith("/service-group"):
                return SERVICE_GROUP_XML
            if xpath.endswith("/service"):
                return SERVICE_XML
            if xpath.endswith("/schedule"):
                return SCHEDULE_XML
            raise AssertionError(f"unexpected xpath {xpath}")

    books = PanosPolicyCollector("panosvm").collect_objects(
        _EmptyAddressClient(), "2026-09-30T00:00:00Z"
    )
    assert len(books) == 1
    assert books[0]["object_book"]["addresses"] == {}
    assert books[0]["object_book"]["address_groups"]["GRP-STATIC"]["kind"] == "static"
