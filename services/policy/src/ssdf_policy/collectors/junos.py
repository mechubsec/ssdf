"""vSRX configured-policy collector: security policies via `| display set` text parser.

Handles both zone-pair policies (`... from-zone X to-zone Y policy NAME ...`) and global
policies (`... global policy NAME ...`, whose zones appear as `match from-zone/to-zone`).
"""

from __future__ import annotations

import ipaddress
import logging

import re

from .base import register

logger = logging.getLogger(__name__)

PROVIDER = "juniper"
_ACTION_MAP = {"permit": "allow", "deny": "deny", "reject": "reject"}
_ZONE_RE = re.compile(r"security policies from-zone (\S+) to-zone (\S+) policy (\S+) (.*)$")
_GLOBAL_RE = re.compile(r"security policies global policy (\S+) (.*)$")

# `show security policies hit-count` (verified live against vsrx-ci, 2026-09-28):
#   Index   From zone        To zone           Name           Policy count  Action
#   1       all-zone         all-zone          default-policy 0             Deny
# Header/banner lines ("Logical system: ...", "Number of policy: N") never start
# with a digit, so they fail this match harmlessly.
_HITCOUNT_RE = re.compile(r"^\s*\d+\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)\s+\S+\s*$")


def _new_rule(name, device_name, from_zone, to_zone, now, order):
    return {
        "provider": PROVIDER,
        "device_name": device_name,
        "rule_name": name,
        "action": "",
        "from_zone": list(from_zone),
        "to_zone": list(to_zone),
        "source_addresses": [],
        "dest_addresses": [],
        "application": [],
        "service": [],
        "position": order,
        "enabled": True,
        "vendor_extras": {},
        "collected_at": now,
        # MEC-992: match clauses the collector used to silently drop. Exclusion
        # flags and scheduler-name are recorded so the caller can decide
        # determinism; the rest (source-identity, dynamic-application,
        # url-category, source-end-user-profile) have no object book behind
        # them yet, so their mere presence flips match_unknown -- a rule using
        # one of these must never be treated as if the clause were absent
        # (today's bug: silently dropped == silently wildcard-matched).
        "source_address_excluded": False,
        "dest_address_excluded": False,
        "source_identity": [],
        "dynamic_application": [],
        "url_category": [],
        "source_end_user_profile": [],
        "scheduler_name": "",
        "match_unknown": False,
    }


# Clauses this collector can parse the tokens of but cannot yet resolve
# deterministically (no object book for identity/AppID/URL-category/EUP
# profiles, and scheduler objects are not collected in this task). A rule
# using any of them is flagged match_unknown rather than silently treated as
# unmatched-clause == wildcard.
_UNRESOLVED_MATCH_FIELDS = (
    "source_identity",
    "dynamic_application",
    "url_category",
    "source_end_user_profile",
)


def parse_security_policies(text: str, device_name: str, now: str) -> list[dict]:
    """Parse Junos `set security policies … | display set` output into rule dicts.

    Terms for the same policy accumulate into one rule. Lines prefixed `inactive:`
    mark the rule disabled. `position` follows first appearance.
    """
    rules: dict[tuple, dict] = {}
    order = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        inactive = line.startswith("inactive:")
        if inactive:
            line = line[len("inactive:") :].strip()
        if not line.startswith("set "):
            continue
        zone_match = _ZONE_RE.search(line)
        if zone_match:
            from_zone, to_zone, name, remainder = zone_match.groups()
            key = ("zonepair", from_zone, to_zone, name)
            seed_from, seed_to = [from_zone], [to_zone]
        else:
            global_match = _GLOBAL_RE.search(line)
            if not global_match:
                continue
            name, remainder = global_match.groups()
            key = ("global", name)
            seed_from, seed_to = [], []
        rule = rules.get(key)
        if rule is None:
            rule = _new_rule(name, device_name, seed_from, seed_to, now, order)
            rules[key] = rule
            order += 1
        if inactive:
            rule["enabled"] = False
        tokens = remainder.split()
        if not tokens:
            continue
        if tokens[:2] == ["match", "source-address"] and len(tokens) > 2:
            rule["source_addresses"].append(tokens[2])
        elif tokens[:2] == ["match", "destination-address"] and len(tokens) > 2:
            rule["dest_addresses"].append(tokens[2])
        elif tokens[:2] == ["match", "application"] and len(tokens) > 2:
            rule["application"].append(tokens[2])
            rule["service"].append(tokens[2])
        elif tokens[:2] == ["match", "from-zone"] and len(tokens) > 2:
            rule["from_zone"].append(tokens[2])
        elif tokens[:2] == ["match", "to-zone"] and len(tokens) > 2:
            rule["to_zone"].append(tokens[2])
        elif tokens[:2] == ["match", "source-address-excluded"]:
            rule["source_address_excluded"] = True
        elif tokens[:2] == ["match", "destination-address-excluded"]:
            rule["dest_address_excluded"] = True
        elif tokens[:2] == ["match", "source-identity"] and len(tokens) > 2:
            rule["source_identity"].append(tokens[2])
        elif tokens[:2] == ["match", "dynamic-application"] and len(tokens) > 2:
            rule["dynamic_application"].append(tokens[2])
        elif tokens[:2] == ["match", "url-category"] and len(tokens) > 2:
            rule["url_category"].append(tokens[2])
        elif tokens[:2] == ["match", "source-end-user-profile"] and len(tokens) > 2:
            rule["source_end_user_profile"].append(tokens[2])
        elif tokens[:1] == ["scheduler-name"] and len(tokens) > 1:
            # Sibling of match/then under `policy NAME`, not a match condition
            # itself -- e.g. `set ... policy P1 scheduler-name BUSINESS-HOURS`.
            rule["scheduler_name"] = tokens[1]
        elif tokens[:1] == ["then"] and len(tokens) > 1:
            mapped = _ACTION_MAP.get(tokens[1])
            if mapped:
                rule["action"] = mapped
        elif tokens[:1] == ["description"]:
            pass
        elif tokens[:1] == ["match"]:
            # Any match sub-clause not explicitly handled above (a future
            # Junos keyword, or one of the above with a malformed/missing
            # value). MEC-992 review (F3): this must never silently vanish
            # and read as a wildcard match -- fail closed instead.
            rule["match_unknown"] = True
            rule["vendor_extras"].setdefault("unparsed_match", []).append(
                tokens[1] if len(tokens) > 1 else ""
            )
        else:
            # Any other unrecognized policy-level keyword. Same rationale as
            # the unparsed-match branch above.
            rule["match_unknown"] = True
    for key, rule in rules.items():
        if key[0] == "global":
            if not rule["from_zone"]:
                rule["from_zone"] = ["any"]
            if not rule["to_zone"]:
                rule["to_zone"] = ["any"]
        # scheduler-name is only deterministic once the scheduler object
        # itself is resolved; this task does not collect scheduler objects,
        # so treat any scheduler-bound rule as unknown rather than assume
        # "always active".
        if any(rule[field] for field in _UNRESOLVED_MATCH_FIELDS) or rule["scheduler_name"]:
            rule["match_unknown"] = True
    return list(rules.values())


def parse_hit_counts(text: str) -> dict[str, int]:
    """Parse `show security policies hit-count` into {rule_name: count}.

    Matched by policy name only: Junos policy names are unique across a device's
    zone-pair + global policy set in the overwhelming common case, but the
    hit-count table (unlike `| display set`) carries no from-zone/to-zone
    linkage back to a rule's own match clauses to key on instead. A name reused
    across two distinct zone-pairs (or across chassis-cluster node sections) is
    therefore ambiguous -- silently keeping the last-seen row would attribute
    one zone-pair's counter to both rules. Since a false "unused" verdict can
    get a live rule deleted (see rule_tools.py), an ambiguous name is dropped
    entirely so the caller leaves hit_count unset and unused_rules reports
    "unknown" for it, never a guessed count. Session/byte usage is unaffected:
    it still tracks correctly via ssdf.rule_usage_hourly, which does not share
    this ambiguity.
    """
    counts: dict[str, int] = {}
    ambiguous: set[str] = set()
    for line in text.splitlines():
        match = _HITCOUNT_RE.match(line)
        if not match:
            continue
        _from_zone, _to_zone, name, count = match.groups()
        if name in counts or name in ambiguous:
            ambiguous.add(name)
            counts.pop(name, None)
            continue
        counts[name] = int(count)
    return counts


_ADDR_BOOK_RE = re.compile(r"^security address-book (\S+) (.*)$")
_ZONE_ADDR_BOOK_RE = re.compile(r"^security zones security-zone (\S+) address-book (.*)$")
_APPLICATIONS_RE = re.compile(r"^applications (.*)$")
_GROUP_APPLICATIONS_RE = re.compile(r"^groups junos-defaults applications (.*)$")


def _empty_book() -> dict:
    return {"addresses": {}, "address_sets": {}, "attached_zones": []}


def _apply_address_tokens(book: dict, tokens: list[str]) -> None:
    """Apply one `address ...` / `address-set ...` / `attach zone ...` remainder
    to a book dict.

    `tokens` is everything after the book name, e.g. `["address", "A1", "10.1.1.0/24"]`
    or `["address-set", "S1", "address", "A1"]`.
    """
    if tokens[:1] == ["address"] and len(tokens) >= 3:
        name = tokens[1]
        rest = tokens[2:]
        if rest[0] == "dns-name":
            book["addresses"][name] = {"kind": "unknown", "reason": "dns-name"}
        elif rest[0] == "range-address" and len(rest) >= 3 and rest[2] == "to":
            book["addresses"][name] = {
                "kind": "range",
                "low": rest[1],
                "high": rest[3] if len(rest) > 3 else "",
            }
        elif rest[0] == "wildcard-address" and len(rest) >= 2:
            book["addresses"][name] = {"kind": "wildcard", "value": rest[1]}
        elif rest[0] == "description":
            # Sibling of the address value, not a replacement for it --
            # `address A1 10.1.1.0/24` followed by `address A1 description
            # web` must not overwrite A1's value with the word "description"
            # (MEC-992 review F6).
            pass
        else:
            # Only accept this as an IP literal if it actually parses as one;
            # an unrecognized keyword here (some future address-book leaf)
            # must not be silently stored as though it were the address
            # value (MEC-992 review F6).
            try:
                ipaddress.ip_network(rest[0], strict=False)
            except ValueError:
                book["addresses"][name] = {"kind": "unknown", "reason": "unparsed"}
            else:
                book["addresses"][name] = {"kind": "address", "value": rest[0]}
    elif tokens[:1] == ["address-set"] and len(tokens) >= 4:
        set_name = tokens[1]
        entry = book["address_sets"].setdefault(set_name, {"members": []})
        if tokens[2] in ("address", "address-set"):
            entry["members"].append(tokens[3])
    elif tokens[:2] == ["attach", "zone"] and len(tokens) >= 3:
        # Records which zone(s) this book is attached to so a rule's `from-zone`
        # can be resolved against the right book instead of guessing between
        # two books that both define the same address name (MEC-992 review F7).
        book["attached_zones"].append(tokens[2])


def parse_address_book(text: str) -> dict[str, dict]:
    """Parse `show configuration security address-book | display set` (plus the
    legacy per-zone `security zones security-zone Z address-book ...` form) into
    `{book_name: {"addresses": {...}, "address_sets": {...}}}`.

    Global book is keyed `"global"` (or whatever name it was attached under);
    zone books are keyed `"zone:<zone>"`. `dns-name` addresses resolve to
    `{"kind": "unknown", ...}` per MEC-992 §1.2 -- deliberately not treated as
    any particular IP so a rule referencing one is never silently narrower or
    wider than it actually is.
    """
    books: dict[str, dict] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line.startswith("set "):
            continue
        line = line[len("set ") :]
        zone_match = _ZONE_ADDR_BOOK_RE.match(line)
        if zone_match:
            zone, remainder = zone_match.groups()
            book = books.setdefault(f"zone:{zone}", _empty_book())
            _apply_address_tokens(book, remainder.split())
            continue
        addr_match = _ADDR_BOOK_RE.match(line)
        if addr_match:
            book_name, remainder = addr_match.groups()
            book = books.setdefault(book_name, _empty_book())
            _apply_address_tokens(book, remainder.split())
    return books


_ALLOWED_APPLICATION_FIELDS = ("protocol", "destination-port", "source-port", "inactivity-timeout")


def _apply_application_tokens(apps: dict, app_sets: dict, tokens: list[str]) -> None:
    if tokens[:1] == ["application"] and len(tokens) >= 3:
        name = tokens[1]
        entry = apps.setdefault(name, {"kind": "application"})
        if entry.get("kind") == "unknown":
            # Already flagged unknown by an earlier line for this same
            # application (multi-term or unrecognized field) -- once flagged,
            # stays flagged regardless of what other lines say about it.
            return
        field = tokens[2]
        if field == "term":
            # Multi-term applications (`application X term T1 protocol tcp
            # ...`) are not parsed per-term here: reading only tokens[2] would
            # silently drop every term's protocol/port and let the rule read
            # as "any" (MEC-992 review F1).
            apps[name] = {"kind": "unknown", "reason": "multi-term"}
            return
        if field not in _ALLOWED_APPLICATION_FIELDS:
            # Any field outside the allowlist (uuid, rpc-program-number,
            # icmp-type, icmp-code, application-protocol, ether-type, ...)
            # must not be silently dropped -- it can change what the
            # application matches (MEC-992 review F1).
            apps[name] = {"kind": "unknown", "reason": "unrecognized-field"}
            return
        value = tokens[3] if len(tokens) > 3 else ""
        entry[field.replace("-", "_")] = value
    elif tokens[:1] == ["application-set"] and len(tokens) >= 4:
        set_name = tokens[1]
        entry = app_sets.setdefault(set_name, {"members": []})
        if tokens[2] in ("application", "application-set"):
            entry["members"].append(tokens[3])


def parse_applications(text: str) -> dict[str, dict]:
    """Parse `show configuration applications | display set` into
    `{"applications": {name: {...}}, "application_sets": {name: {"members": [...]}}}`.

    Custom applications only -- predefined `junos-*` applications live under
    `groups junos-defaults applications` and are parsed separately by
    `parse_predefined_applications` (confirmed read-only-readable on vsrx-ci,
    2026-09-30: `show configuration groups junos-defaults applications | display set`).
    """
    apps: dict[str, dict] = {}
    app_sets: dict[str, dict] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line.startswith("set "):
            continue
        line = line[len("set ") :]
        match = _APPLICATIONS_RE.match(line)
        if not match:
            continue
        _apply_application_tokens(apps, app_sets, match.group(1).split())
    return {"applications": apps, "application_sets": app_sets}


def parse_predefined_applications(text: str) -> dict[str, dict]:
    """Parse `show configuration groups junos-defaults applications | display set`
    into `{"applications": {name: {...}}, "application_sets": {name: {"members": [...]}}}`
    -- the built-in `junos-*` application catalog. Same token shape as a
    custom `applications application NAME ...` stanza, just nested one level
    deeper under `groups junos-defaults`.

    Predefined application-*sets* (e.g. `junos-cifs`) are returned alongside
    the individual applications, not discarded -- a rule matching on one of
    those sets could not otherwise be resolved (MEC-992 review F2).
    """
    apps: dict[str, dict] = {}
    app_sets: dict[str, dict] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line.startswith("set "):
            continue
        line = line[len("set ") :]
        match = _GROUP_APPLICATIONS_RE.match(line)
        if not match:
            continue
        _apply_application_tokens(apps, app_sets, match.group(1).split())
    return {"applications": apps, "application_sets": app_sets}


@register("junos")
class JunosPolicyCollector:
    """Collects configured security policies from one or more vSRX devices."""

    name = "junos"

    def __init__(self, devices: list[str] | None = None):
        self.devices = devices or []

    def collect(self, client, now: str) -> list[dict]:
        """Read each device's configured policy, skipping ones that fail.

        Per-device resilient: run_collectors catches at collector granularity, so
        an uncaught error here would discard every other device's rules too.
        """
        rules: list[dict] = []
        for dev in self.devices:
            try:
                text = client.call_tool(
                    "execute_junos_command",
                    {
                        "router_name": dev,
                        "command": "show configuration security policies | display set",
                    },
                )
            except Exception:
                logger.warning("junos device %r unreachable; skipping", dev, exc_info=True)
                continue
            try:
                dev_rules = parse_security_policies(text, dev, now)
            except Exception:
                logger.warning("junos %r: policy parse failed; continuing", dev, exc_info=True)
                continue
            # MEC-566: read-only hit-count enrichment via the same execute_junos_command
            # tool/token already used above -- no new device write path. A failure here
            # must not drop the device's configured rules, only leave hit_count unset
            # (downstream tools treat a missing hit_count as "unknown", never "unused").
            try:
                hc_text = client.call_tool(
                    "execute_junos_command",
                    {"router_name": dev, "command": "show security policies hit-count"},
                )
                hit_counts = parse_hit_counts(hc_text)
                for rule in dev_rules:
                    count = hit_counts.get(rule["rule_name"])
                    if count is not None:
                        rule["vendor_extras"]["hit_count"] = str(count)
                        rule["vendor_extras"]["hit_count_collected_at"] = now
            except Exception:
                logger.warning(
                    "junos %r: hit-count collection failed; continuing without counters",
                    dev,
                    exc_info=True,
                )
            rules.extend(dev_rules)
        return rules

    def collect_objects(self, client, now: str) -> list[dict]:
        """Read each device's address-book + applications object book (MEC-992).

        Per-device resilient, same rationale as collect(): one device's command
        failure must not discard another device's object book.
        """
        books: list[dict] = []
        for dev in self.devices:
            try:
                addr_text = client.call_tool(
                    "execute_junos_command",
                    {
                        "router_name": dev,
                        "command": "show configuration security address-book | display set",
                    },
                )
                zones_text = client.call_tool(
                    "execute_junos_command",
                    {
                        "router_name": dev,
                        "command": "show configuration security zones | display set",
                    },
                )
                app_text = client.call_tool(
                    "execute_junos_command",
                    {
                        "router_name": dev,
                        "command": "show configuration applications | display set",
                    },
                )
                predefined_text = client.call_tool(
                    "execute_junos_command",
                    {
                        "router_name": dev,
                        "command": "show configuration groups junos-defaults applications | display set",
                    },
                )
            except Exception:
                logger.warning(
                    "junos device %r unreachable; skipping object book", dev, exc_info=True
                )
                continue
            try:
                address_books = parse_address_book(addr_text + "\n" + zones_text)
                app_result = parse_applications(app_text)
                predefined = parse_predefined_applications(predefined_text)
            except Exception:
                logger.warning("junos %r: object book parse failed; skipping", dev, exc_info=True)
                continue
            books.append(
                {
                    "provider": PROVIDER,
                    "device_name": dev,
                    "collected_at": now,
                    "object_book": {
                        "address_books": address_books,
                        "applications": app_result["applications"],
                        "application_sets": app_result["application_sets"],
                        "predefined_applications": predefined["applications"],
                        "predefined_application_sets": predefined["application_sets"],
                    },
                }
            )
        return books
