"""PAN-OS configured-policy collector: security rulebase via get_panos_config (XML/JSON)."""

from __future__ import annotations

import logging
from defusedxml.ElementTree import fromstring as _xml_fromstring, ParseError as _XmlParseError
import xml.etree.ElementTree as ET  # type annotations only (ET.Element)

from ssdf_common.mcp_envelope import envelope_truncated, unwrap_mcp_text

from .base import register
from .matchunknown import derive_match_unknown

logger = logging.getLogger(__name__)

PROVIDER = "paloalto"

# vsys1 security rulebase — the only subtree this collector needs.
RULES_XPATH = "/config/devices/entry/vsys/entry[@name='vsys1']/rulebase/security"


def _root(text: str) -> ET.Element | None:
    """Unwrap an optional JSON envelope and parse to an XML root element."""
    xml_text = unwrap_mcp_text(text)
    try:
        return _xml_fromstring(xml_text)
    except (_XmlParseError, Exception) as exc:  # ParseError + defused entity/DTD errors
        logger.warning("panos: failed to parse config XML: %s", exc)
        return None


def _rule_entries(root: ET.Element) -> list[ET.Element]:
    """Locate the vsys security rulebase rule entries, regardless of envelope.

    Handles the full running-config (`.//rulebase/security/rules`) and a bare
    `<rules>` root. Deliberately scoped so zone/address/user `<entry>` elements
    elsewhere in the config are never mistaken for security rules.
    """
    rules_el = root.find(".//rulebase/security/rules")
    if rules_el is None:
        if root.tag == "rules":
            rules_el = root
        else:
            rules_el = root.find(".//security/rules")
            if rules_el is None:
                rules_el = root.find(".//rules")
    return rules_el.findall("entry") if rules_el is not None else []


def _members(entry: ET.Element, tag: str) -> list[str]:
    el = entry.find(tag)
    if el is None:
        return []
    return [m.text.strip() for m in el.findall("member") if m.text and m.text.strip()]


def _text(entry: ET.Element, tag: str) -> str:
    el = entry.find(tag)
    return el.text.strip() if el is not None and el.text else ""


def parse_security_rules(text: str, device_name: str, now: str) -> list[dict]:
    """Parse a PAN-OS security rulebase into normalized rule dicts (order preserved)."""
    root = _root(text)
    if root is None:
        return []
    rules: list[dict] = []
    for position, entry in enumerate(_rule_entries(root)):
        name = entry.get("name", "").strip()
        if not name:
            continue
        rule = {
            "provider": PROVIDER,
            "device_name": device_name,
            "rule_name": name,
            "action": _text(entry, "action"),
            "from_zone": _members(entry, "from"),
            "to_zone": _members(entry, "to"),
            "source_addresses": _members(entry, "source"),
            "dest_addresses": _members(entry, "destination"),
            "application": _members(entry, "application"),
            "service": _members(entry, "service"),
            "position": position,
            "enabled": _text(entry, "disabled").lower() != "yes",
            "vendor_extras": {"panw.panos.uuid": entry.get("uuid", "")},
            "collected_at": now,
            "negate_source": _text(entry, "negate-source").lower() == "yes",
            "negate_destination": _text(entry, "negate-destination").lower() == "yes",
            "schedule": _text(entry, "schedule"),
            "source_user": _members(entry, "source-user"),
            "url_category": _members(entry, "category"),
            "source_hip": _members(entry, "source-hip"),
            "destination_hip": _members(entry, "destination-hip"),
        }
        rule["match_unknown"] = derive_match_unknown(rule, PROVIDER)
        rules.append(rule)
    return rules


def parse_rule_hit_counts(text: str) -> dict[str, int]:
    """Parse a `show rule-hit-count` XML response into {rule_name: count}.

    Schema per the PAN-OS XML API operational-command docs (`<rule-hit-count>` ->
    `<vsys>` -> `<rule-base>` -> `<rules>` -> `<entry name="...">` ->
    `<hit-count>N</hit-count>`). NOT live-verified: no PAN-OS lab device was
    available for this change (unlike the Junos hit-count parser in junos.py,
    which WAS verified live against vsrx-ci). Walks all `<entry>` elements
    rather than the exact nested path so an envelope/depth difference between
    PAN-OS versions degrades to "no counters found", not a parse error --
    which also means a name can legitimately repeat (multiple vsys, multiple
    rulebases/lsys, cluster peers echoing the same op command). Keeping the
    last-seen row for a repeated name would attribute one rulebase's counter
    to every rule sharing that name; since a false "unused" verdict can get a
    live rule deleted (see rule_tools.py), an ambiguous name is dropped
    entirely so the caller leaves hit_count unset and unused_rules reports
    "unknown" for it instead of guessing.
    """
    root = _root(text)
    if root is None:
        return {}
    counts: dict[str, int] = {}
    ambiguous: set[str] = set()
    for entry in root.iter("entry"):
        hit_count_el = entry.find("hit-count")
        if hit_count_el is None or hit_count_el.text is None:
            continue
        name = entry.get("name", "").strip()
        if not name:
            continue
        try:
            count = int(hit_count_el.text.strip())
        except ValueError:
            continue
        if name in counts or name in ambiguous:
            ambiguous.add(name)
            counts.pop(name, None)
            continue
        counts[name] = count
    return counts


# Read-only op command: all security rules, all vsys (M6b's collector already
# scopes to vsys1 for config; hit-count is requested the same way).
_HITCOUNT_OP_COMMAND = (
    "<show><rule-hit-count><vsys><entry name='vsys1'><rule-base>"
    "<entry name='security'><rules><all/></rules></entry>"
    "</rule-base></entry></vsys></rule-hit-count></show>"
)


ADDRESS_XPATH = "/config/devices/entry/vsys/entry[@name='vsys1']/address"
ADDRESS_GROUP_XPATH = "/config/devices/entry/vsys/entry[@name='vsys1']/address-group"
SERVICE_XPATH = "/config/devices/entry/vsys/entry[@name='vsys1']/service"
SERVICE_GROUP_XPATH = "/config/devices/entry/vsys/entry[@name='vsys1']/service-group"
SCHEDULE_XPATH = "/config/devices/entry/vsys/entry[@name='vsys1']/schedule"


def _object_entries(root: ET.Element) -> list[ET.Element]:
    """Locate `<entry>` object definitions regardless of get_panos_config's envelope
    (full `<config>` doc, a bare `<address>`/`<address-group>`/... container, or a
    bare list of `<entry>`)."""
    if root.tag == "entry":
        return [root]
    entries = root.findall("entry")
    if entries:
        return entries
    for child in root:
        entries = child.findall("entry")
        if entries:
            return entries
    return []


def parse_address_objects(text: str) -> dict[str, dict]:
    """Parse a PAN-OS `<address>` container into `{name: {...}}`.

    Static objects only (ip-netmask, ip-range, fqdn); `fqdn` resolves to
    `{"kind": "unknown", "reason": "fqdn"}` since it is not resolvable without
    a live DNS lookup at collection time.
    """
    root = _root(text)
    if root is None:
        return {}
    objects: dict[str, dict] = {}
    for entry in _object_entries(root):
        name = entry.get("name", "").strip()
        if not name:
            continue
        if val := _text(entry, "ip-netmask"):
            objects[name] = {"kind": "ip-netmask", "value": val}
        elif val := _text(entry, "ip-range"):
            objects[name] = {"kind": "ip-range", "value": val}
        elif val := _text(entry, "ip-wildcard"):
            objects[name] = {"kind": "ip-wildcard", "value": val}
        elif _text(entry, "fqdn"):
            objects[name] = {"kind": "unknown", "reason": "fqdn"}
        else:
            objects[name] = {"kind": "unknown", "reason": "unrecognized-address-type"}
    return objects


def parse_address_groups(text: str) -> dict[str, dict]:
    """Parse a PAN-OS `<address-group>` container into `{name: {...}}`.

    Static groups only, per MEC-992 §5 -- dynamic address groups (DAG,
    tag-based `<dynamic><filter>`) are out of scope and resolve to
    `{"kind": "unknown", "reason": "dynamic-address-group"}`.
    """
    root = _root(text)
    if root is None:
        return {}
    groups: dict[str, dict] = {}
    for entry in _object_entries(root):
        name = entry.get("name", "").strip()
        if not name:
            continue
        if entry.find("dynamic") is not None:
            groups[name] = {"kind": "unknown", "reason": "dynamic-address-group"}
        else:
            groups[name] = {"kind": "static", "members": _members(entry, "static")}
    return groups


def _service_protocol(entry: ET.Element) -> dict:
    protocol_el = entry.find("protocol")
    if protocol_el is None:
        return {}
    for proto in ("tcp", "udp"):
        proto_el = protocol_el.find(proto)
        if proto_el is not None:
            return {
                "protocol": proto,
                "port": _text(proto_el, "port"),
                "source_port": _text(proto_el, "source-port"),
            }
    return {}


def parse_service_objects(text: str) -> dict[str, dict]:
    """Parse a PAN-OS `<service>` container into `{name: {"protocol", "port", ...}}`."""
    root = _root(text)
    if root is None:
        return {}
    services: dict[str, dict] = {}
    for entry in _object_entries(root):
        name = entry.get("name", "").strip()
        if not name:
            continue
        services[name] = _service_protocol(entry) or {
            "kind": "unknown",
            "reason": "unrecognized-protocol",
        }
    return services


def parse_service_groups(text: str) -> dict[str, dict]:
    """Parse a PAN-OS `<service-group>` container into `{name: {"members": [...]}}`."""
    root = _root(text)
    if root is None:
        return {}
    groups: dict[str, dict] = {}
    for entry in _object_entries(root):
        name = entry.get("name", "").strip()
        if not name:
            continue
        groups[name] = {"members": _members(entry, "members")}
    return groups


def parse_schedules(text: str) -> dict[str, dict]:
    """Parse a PAN-OS `<schedule>` container into `{name: {}}`.

    Presence/name only: schedule *evaluation* (whether it is currently active)
    is the change_impact evaluator's job (task C of MEC-570), not this
    collector's -- this just makes sure a rule's `schedule` binding resolves
    to a known object rather than an unresolvable string.
    """
    root = _root(text)
    if root is None:
        return {}
    return {
        entry.get("name", "").strip(): {}
        for entry in _object_entries(root)
        if entry.get("name", "").strip()
    }


@register("panos")
class PanosPolicyCollector:
    """Collects the configured security rulebase from one PAN-OS firewall."""

    name = "panos"

    def __init__(self, device: str = "panosvm"):
        self.device = device

    def collect(self, client, now: str) -> list[dict]:
        """Read the device's configured security rulebase.

        Scoped to RULES_XPATH rather than pulling the whole running config: the
        tool caps output at 512 KiB by default, and the full config is several
        times larger than the rulebase for no benefit here.
        """
        text = client.call_tool("get_panos_config", {"device": self.device, "xpath": RULES_XPATH})
        if envelope_truncated(text):
            # Parsing a cut-short rulebase would drop real rules and read
            # downstream as though policy had been deleted. Refuse instead.
            raise RuntimeError(
                f"panos {self.device}: get_panos_config returned a truncated "
                "rulebase; refusing to emit a partial policy set"
            )
        rules = parse_security_rules(text, self.device, now)
        # MEC-566: read-only hit-count enrichment via execute_panos_op (same
        # read-only op-command surface, no new device write path). A failure here
        # must not drop the device's configured rules, only leave hit_count unset
        # (downstream tools treat a missing hit_count as "unknown", never "unused").
        try:
            hc_text = client.call_tool(
                "execute_panos_op",
                {"device": self.device, "command": _HITCOUNT_OP_COMMAND},
            )
            hit_counts = parse_rule_hit_counts(hc_text)
            for rule in rules:
                count = hit_counts.get(rule["rule_name"])
                if count is not None:
                    rule["vendor_extras"]["hit_count"] = str(count)
                    rule["vendor_extras"]["hit_count_collected_at"] = now
        except Exception:
            logger.warning(
                "panos %r: hit-count collection failed; continuing without counters",
                self.device,
                exc_info=True,
            )
        return rules

    def collect_objects(self, client, now: str) -> list[dict]:
        """Read the device's address/service object book (MEC-992).

        Each xpath is fetched independently, but a failed fetch, a truncated
        envelope, or XML that doesn't parse for ANY one of the five aborts the
        whole device's object book for this pass (returns `[]`) rather than
        emitting a partial book. MEC-992 review (F4): the earlier per-key
        `object_book[key] = {}` behavior looked identical to a legitimately
        empty container (e.g. `<address/>`), so a single transient failure got
        recorded as a genuine "object book changed" row in
        ssdf.object_book_hash -- and every later change_impact query over
        that window silently couldn't resolve a single address. A skipped
        pass leaves the previous hash as the latest-known good one instead.
        """
        fetches = (
            ("addresses", ADDRESS_XPATH, parse_address_objects),
            ("address_groups", ADDRESS_GROUP_XPATH, parse_address_groups),
            ("services", SERVICE_XPATH, parse_service_objects),
            ("service_groups", SERVICE_GROUP_XPATH, parse_service_groups),
            ("schedules", SCHEDULE_XPATH, parse_schedules),
        )
        object_book: dict[str, dict] = {}
        for key, xpath, parser in fetches:
            try:
                text = client.call_tool("get_panos_config", {"device": self.device, "xpath": xpath})
            except Exception:
                logger.warning(
                    "panos %r: %s object fetch failed; refusing object book for this pass",
                    self.device,
                    key,
                    exc_info=True,
                )
                return []
            if envelope_truncated(text):
                logger.warning(
                    "panos %r: %s object fetch truncated; refusing object book for this pass",
                    self.device,
                    key,
                )
                return []
            if _root(text) is None:
                # A container that legitimately has no entries (`<address/>`)
                # still parses to a real Element; only genuinely unparseable
                # XML hits this branch, so this can't misclassify "empty" as
                # "failed".
                logger.warning(
                    "panos %r: %s object fetch did not parse; refusing object book for this pass",
                    self.device,
                    key,
                )
                return []
            try:
                object_book[key] = parser(text)
            except Exception:
                logger.warning(
                    "panos %r: %s object parse failed; refusing object book for this pass",
                    self.device,
                    key,
                    exc_info=True,
                )
                return []
        return [
            {
                "provider": PROVIDER,
                "device_name": self.device,
                "collected_at": now,
                "object_book": object_book,
            }
        ]
