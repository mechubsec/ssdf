"""Proposed-change (Delta) parsing and application (doc §1.1b).

Two input forms, both producing P' = apply(P, Delta) as a plain list of
`NormalizedRule` dicts (the same shape `collectors.{junos,panos}` already
emit):

  (a) a vendor-neutral JSON op list: add/modify/delete/move/enable/disable.
  (b) Junos only: `set`/`delete`/`insert ... before|after`/`activate`/
      `deactivate` lines applied to the current `| display set` text, then
      re-parsed with the existing `parse_security_policies` (reused, not
      reimplemented).

Delta never reaches a device anywhere in this module -- it only ever produces
an in-memory rule list for the evaluator to compare against. SSDF stays
read-only (MEC-559).
"""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass, field
from typing import Any, Literal

from ..collectors.junos import parse_security_policies
from ..collectors.matchunknown import derive_match_unknown

OpKind = Literal["add", "modify", "delete", "move", "enable", "disable"]

# Fields a delta may set directly: the collector's own match/action/enabled
# clauses (see collectors/{junos,panos}.py NormalizedRule shape). Deliberately
# excludes bookkeeping/classification fields the evaluator trusts from the
# collector, not the caller -- e.g. `match_unknown`, `provider`,
# `vendor_extras` -- so a delta can't set those directly.
_ALLOWED_MODIFY_FIELDS = frozenset(
    {
        "action",
        "enabled",
        "from_zone",
        "to_zone",
        "source_addresses",
        "dest_addresses",
        "application",
        "service",
        "source_address_excluded",
        "dest_address_excluded",
        "source_identity",
        "dynamic_application",
        "url_category",
        "source_end_user_profile",
        "scheduler_name",
        "negate_source",
        "negate_destination",
        "schedule",
        "source_user",
        "source_hip",
        "destination_hip",
    }
)
# `add` additionally needs to name and classify the new rule; everything
# else about it (provider, vendor_extras, match_unknown) is derived, never
# taken from the caller's dict.
_ALLOWED_ADD_FIELDS = _ALLOWED_MODIFY_FIELDS | {"rule_name", "is_global"}

# Field-name allowlisting alone isn't enough: a well-typed value matters too
# (e.g. `enabled` as the string "false" is truthy, a zone as a bare string
# instead of a list matches by substring). Each allowed field is checked
# against its collector-emitted shape before a delta op is accepted.
_BOOL_FIELDS = frozenset(
    {
        "enabled",
        "is_global",
        "source_address_excluded",
        "dest_address_excluded",
        "negate_source",
        "negate_destination",
    }
)
_LIST_STR_FIELDS = frozenset(
    {
        "from_zone",
        "to_zone",
        "source_addresses",
        "dest_addresses",
        "application",
        "service",
        "source_identity",
        "dynamic_application",
        "url_category",
        "source_end_user_profile",
        "source_user",
        "source_hip",
        "destination_hip",
    }
)
_STR_FIELDS = frozenset({"scheduler_name", "schedule", "rule_name"})
_ACTIONS_BY_PROVIDER = {
    "juniper": frozenset({"allow", "deny", "reject"}),
    "paloalto": frozenset({"allow", "deny", "drop", "reset-client", "reset-server", "reset-both"}),
}


def _validate_field_value(name: str, value: Any, provider: str, op_index: int) -> None:
    if name == "action":
        valid_actions = _ACTIONS_BY_PROVIDER.get(provider)
        if valid_actions is None or not isinstance(value, str) or value not in valid_actions:
            raise DeltaError(f"delta op {op_index}: field 'action' has invalid type")
        return
    if name in _BOOL_FIELDS:
        if not isinstance(value, bool):
            raise DeltaError(f"delta op {op_index}: field {name!r} has invalid type")
        return
    if name in _LIST_STR_FIELDS:
        if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
            raise DeltaError(f"delta op {op_index}: field {name!r} has invalid type")
        return
    if name in _STR_FIELDS:
        if not isinstance(value, str):
            raise DeltaError(f"delta op {op_index}: field {name!r} has invalid type")
        return
    raise DeltaError(f"delta op {op_index}: field {name!r} has invalid type")


class DeltaError(ValueError):
    """Raised for a Delta that can't be unambiguously applied -- never guessed."""


@dataclass(frozen=True)
class DeltaOp:
    kind: OpKind
    rule_name: str
    from_zone: str | None = None
    to_zone: str | None = None
    rule: dict[str, Any] | None = None  # for "add"
    fields: dict[str, Any] | None = None  # for "modify"
    before: str | None = None  # for "add"/"move"
    after: str | None = None  # for "add"/"move"


@dataclass(frozen=True)
class Delta:
    ops: tuple[DeltaOp, ...] = field(default_factory=tuple)
    source: Literal["json", "junos_text"] = "json"


def _find_rule(
    rules: list[dict], rule_name: str, from_zone: str | None, to_zone: str | None
) -> int:
    matches = [
        i
        for i, r in enumerate(rules)
        if r["rule_name"] == rule_name
        and (from_zone is None or r.get("from_zone") == [from_zone])
        and (to_zone is None or r.get("to_zone") == [to_zone])
    ]
    if not matches:
        raise DeltaError(f"delta references unknown rule {rule_name!r} (from_zone={from_zone!r})")
    if len(matches) > 1:
        raise DeltaError(
            f"rule name {rule_name!r} is ambiguous across contexts; "
            "the op must disambiguate with from_zone/to_zone"
        )
    return matches[0]


def parse_json_delta(ops: list[dict], provider: str) -> Delta:
    """Validate and structure a vendor-neutral JSON op list."""
    parsed: list[DeltaOp] = []
    for i, raw in enumerate(ops):
        kind = raw.get("op")
        if kind not in ("add", "modify", "delete", "move", "enable", "disable"):
            raise DeltaError(f"delta op {i}: unknown op kind {kind!r}")
        if kind == "add":
            rule = raw.get("rule")
            if not isinstance(rule, dict) or not rule.get("rule_name"):
                raise DeltaError(f"delta op {i}: 'add' requires a full rule dict with rule_name")
            disallowed = set(rule) - _ALLOWED_ADD_FIELDS
            if disallowed:
                raise DeltaError(
                    f"delta op {i}: 'add' must not set internal field(s) {sorted(disallowed)}"
                )
            for name, value in rule.items():
                _validate_field_value(name, value, provider, i)
            parsed.append(
                DeltaOp(
                    kind="add",
                    rule_name=rule["rule_name"],
                    rule=rule,
                    before=raw.get("before"),
                    after=raw.get("after"),
                )
            )
            continue
        rule_name = raw.get("rule_name")
        if not rule_name:
            raise DeltaError(f"delta op {i} ({kind}): missing rule_name")
        if kind == "modify":
            fields = raw.get("fields")
            if not isinstance(fields, dict) or not fields:
                raise DeltaError(f"delta op {i}: 'modify' requires non-empty 'fields'")
            if "position" in fields:
                raise DeltaError(
                    f"delta op {i}: 'modify' must not set 'position' directly; use 'move' "
                    "to change order"
                )
            disallowed = set(fields) - _ALLOWED_MODIFY_FIELDS
            if disallowed:
                raise DeltaError(
                    f"delta op {i}: 'modify' must not set internal field(s) {sorted(disallowed)}"
                )
            for name, value in fields.items():
                _validate_field_value(name, value, provider, i)
            parsed.append(
                DeltaOp(
                    kind="modify",
                    rule_name=rule_name,
                    from_zone=raw.get("from_zone"),
                    to_zone=raw.get("to_zone"),
                    fields=fields,
                )
            )
        elif kind == "move":
            if not raw.get("before") and not raw.get("after"):
                raise DeltaError(f"delta op {i}: 'move' requires 'before' or 'after'")
            parsed.append(
                DeltaOp(
                    kind="move",
                    rule_name=rule_name,
                    from_zone=raw.get("from_zone"),
                    to_zone=raw.get("to_zone"),
                    before=raw.get("before"),
                    after=raw.get("after"),
                )
            )
        else:  # delete, enable, disable
            parsed.append(
                DeltaOp(
                    kind=kind,
                    rule_name=rule_name,
                    from_zone=raw.get("from_zone"),
                    to_zone=raw.get("to_zone"),
                )
            )
    return Delta(ops=tuple(parsed), source="json")


def renumber_positions(rules: list[dict]) -> list[dict]:
    """Return a copy of `rules` reordered by the existing `position` field
    (stable, so ties keep their input order) and renumbered 0..n-1 in that
    order -- the single scale every caller of `compile_rulebase` must agree
    on. The caller-supplied list order for P is not trustworthy on its own
    (e.g. `configured_policies_for_firewalls` returns entities in SQL join
    order, not rulebase order); this normalizes P onto the same scale
    `apply_delta` produces for P', so a before/after position comparison
    (`diff.diff_rulebases`, `evaluator.firstmatch3`) is never comparing a
    trusted value against a stale one.
    """
    ordered = sorted(copy.deepcopy(rules), key=lambda r: int(r.get("position", 0) or 0))
    for i, rule in enumerate(ordered):
        rule["position"] = i
    return ordered


_ADD_LIST_DEFAULTS = (
    "from_zone",
    "to_zone",
    "source_addresses",
    "dest_addresses",
    "application",
    "service",
    "source_identity",
    "dynamic_application",
    "url_category",
    "source_end_user_profile",
    "source_user",
    "source_hip",
    "destination_hip",
)
_ADD_STR_DEFAULTS = ("action", "scheduler_name", "schedule")
_ADD_BOOL_DEFAULTS = (
    "source_address_excluded",
    "dest_address_excluded",
    "negate_source",
    "negate_destination",
)


def apply_delta(rules: list[dict], delta: Delta, provider: str | None = None) -> list[dict]:
    """P' = apply(P, Delta) for the JSON-op form. Pure: `rules` is not mutated.

    The working list is first ordered by each rule's existing `position` (so
    an "insert at index N" / "move before/after" op lands relative to the
    rulebase's *true* order, not whatever order the caller's list happened to
    be in), then every op is applied via list index, and finally `position`
    is reassigned from the resulting list order, so `diff_rulebases` and
    `firstmatch3` -- which trust `position`, not list order -- always see
    the result of a reorder.

    `provider` is only needed to construct a brand-new rule for an `add` op
    (its `provider`/`match_unknown` are derived here, never taken from the
    caller's dict); it defaults to the existing rulebase's own provider when
    not given. `modify` and `add` both recompute `match_unknown` from the
    resulting rule's own fields, OR'd with whatever was already set -- a
    delta can narrow or widen the clauses that made a rule `match_unknown`,
    but can never directly clear the flag itself.
    """
    result = renumber_positions(rules)
    if provider is None and result:
        provider = result[0]["provider"]
    for op in delta.ops:
        if op.kind == "add":
            if provider is None:
                raise DeltaError("'add' requires a provider when the rulebase is empty")
            new_rule = copy.deepcopy(op.rule)
            new_rule.setdefault("enabled", True)
            new_rule.setdefault("is_global", False)
            for field in _ADD_LIST_DEFAULTS:
                new_rule.setdefault(field, [])
            for field in _ADD_STR_DEFAULTS:
                new_rule.setdefault(field, "")
            for field in _ADD_BOOL_DEFAULTS:
                new_rule.setdefault(field, False)
            new_rule["provider"] = provider
            new_rule["vendor_extras"] = {}
            new_rule["match_unknown"] = derive_match_unknown(new_rule, provider)
            insert_at = len(result)
            if op.before is not None:
                insert_at = _find_rule(result, op.before, None, None)
            elif op.after is not None:
                insert_at = _find_rule(result, op.after, None, None) + 1
            result.insert(insert_at, new_rule)
        elif op.kind == "delete":
            idx = _find_rule(result, op.rule_name, op.from_zone, op.to_zone)
            result.pop(idx)
        elif op.kind == "modify":
            idx = _find_rule(result, op.rule_name, op.from_zone, op.to_zone)
            rule = result[idx]
            rule.update(copy.deepcopy(op.fields))
            rule["match_unknown"] = bool(rule.get("match_unknown")) or derive_match_unknown(
                rule, rule["provider"]
            )
        elif op.kind in ("enable", "disable"):
            idx = _find_rule(result, op.rule_name, op.from_zone, op.to_zone)
            result[idx]["enabled"] = op.kind == "enable"
        elif op.kind == "move":
            idx = _find_rule(result, op.rule_name, op.from_zone, op.to_zone)
            moved = result.pop(idx)
            if op.before is not None:
                dest = _find_rule(result, op.before, None, None)
            else:
                dest = _find_rule(result, op.after, None, None) + 1
            result.insert(dest, moved)
        else:  # pragma: no cover - exhaustive OpKind
            raise DeltaError(f"unhandled op kind {op.kind!r}")
    for i, rule in enumerate(result):
        rule["position"] = i
    return result


# ---------------------------------------------------------------------------
# Junos `| display set` text delta (form b)
# ---------------------------------------------------------------------------

_POLICY_PREFIX_RE = re.compile(
    r"^(security policies from-zone \S+ to-zone \S+ policy \S+|security policies global policy \S+)"
)
# Short form: a bare policy name on each side. Ambiguous whenever that name
# exists in more than one from-zone/to-zone context -- `_resolve_insert`
# below refuses to guess and raises instead of silently taking the first
# match, which is what real Junos `insert security policies ... policy X
# before|after policy Y` syntax (the full form, also accepted below) exists
# to disambiguate.
_INSERT_SHORT_RE = re.compile(r"^insert\s+(\S+)\s+(before|after)\s+(\S+)\s*$")
_INSERT_FULL_ZONEPAIR_RE = re.compile(
    r"^insert\s+security policies from-zone (\S+) to-zone (\S+) policy (\S+)\s+"
    r"(before|after)\s+policy\s+(\S+)\s*$"
)
_INSERT_FULL_GLOBAL_RE = re.compile(
    r"^insert\s+security policies global policy (\S+)\s+(before|after)\s+policy\s+(\S+)\s*$"
)


def _policy_key_for_line(line: str) -> str | None:
    match = _POLICY_PREFIX_RE.match(line)
    return match.group(1) if match else None


def _group_lines(text: str) -> list[tuple[str, list[str]]]:
    """Group `set`/`inactive: set` lines by policy identifier, preserving
    first-appearance order -- the same grouping `parse_security_policies` uses
    internally, exposed here so deltas can move/add/remove whole groups."""
    order: list[str] = []
    groups: dict[str, list[str]] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        body = line[len("inactive:") :].strip() if line.startswith("inactive:") else line
        if not body.startswith("set "):
            continue
        key = _policy_key_for_line(body[len("set ") :])
        if key is None:
            continue
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(line)
    return [(key, groups[key]) for key in order]


def _flatten(groups: list[tuple[str, list[str]]]) -> str:
    return "\n".join(line for _key, lines in groups for line in lines)


def _find_group_by_short_name(groups: list[tuple[str, list[str]]], name: str, lineno: int) -> int:
    """Resolve a bare policy name to exactly one group, or fail closed.

    A name match against more than one group (the same policy name used in
    two different from-zone/to-zone contexts, or alongside a `global`
    policy) is ambiguous: silently taking the first match can reorder the
    wrong context's policy. Raise instead and tell the caller to use the
    fully-qualified form.
    """
    matches = [i for i, (k, _l) in enumerate(groups) if k.endswith(f"policy {name}")]
    if len(matches) > 1:
        raise DeltaError(
            f"delta line {lineno}: policy name is ambiguous across from-zone/to-zone "
            "contexts; use the full 'insert security policies from-zone A to-zone B "
            "policy X before|after policy Y' form to disambiguate"
        )
    if not matches:
        raise DeltaError(f"delta line {lineno}: insert references unknown policy")
    return matches[0]


def _resolve_insert(
    line: str, groups: list[tuple[str, list[str]]], lineno: int
) -> tuple[int, int, str] | None:
    """Return (moved_idx, sibling_idx, where) if `line` is any supported
    `insert` form, else None. The full Junos form resolves both sides to a
    fully zone-qualified key, so there's never ambiguity; the short bare-name
    form must resolve to exactly one group on each side."""
    full_zp = _INSERT_FULL_ZONEPAIR_RE.match(line)
    if full_zp:
        fz, tz, name, where, sibling = full_zp.groups()
        moved_key = f"security policies from-zone {fz} to-zone {tz} policy {name}"
        sibling_key = f"security policies from-zone {fz} to-zone {tz} policy {sibling}"
        index = {key: i for i, (key, _lines) in enumerate(groups)}
        if moved_key not in index or sibling_key not in index:
            raise DeltaError(f"delta line {lineno}: insert references unknown policy")
        return index[moved_key], index[sibling_key], where

    full_global = _INSERT_FULL_GLOBAL_RE.match(line)
    if full_global:
        name, where, sibling = full_global.groups()
        moved_key = f"security policies global policy {name}"
        sibling_key = f"security policies global policy {sibling}"
        index = {key: i for i, (key, _lines) in enumerate(groups)}
        if moved_key not in index or sibling_key not in index:
            raise DeltaError(f"delta line {lineno}: insert references unknown policy")
        return index[moved_key], index[sibling_key], where

    short = _INSERT_SHORT_RE.match(line)
    if short:
        name, where, sibling = short.groups()
        moved_idx = _find_group_by_short_name(groups, name, lineno)
        sibling_idx = _find_group_by_short_name(groups, sibling, lineno)
        return moved_idx, sibling_idx, where

    return None


def apply_junos_set_delta(current_text: str, delta_lines: list[str]) -> str:
    """Apply `set`/`delete`/`insert ... before|after`/`activate`/`deactivate`
    lines to `current_text` (the current `| display set` output) and return
    the resulting display-set text. The caller re-parses it with
    `parse_security_policies` to get P'.

    Every `DeltaError` raised here identifies the offending line by index
    only, never by echoing its text: `apply_junos_text_delta`'s caller
    (services/mcp-query's `audited_tool` wrapper) records `str(exc)` in
    `ssdf.audit` verbatim on the error path, so embedding the line itself
    would make a rejected (and therefore unvetted) delta line the leak.
    """
    groups = _group_lines(current_text)
    index = {key: i for i, (key, _lines) in enumerate(groups)}

    def _group_for(key: str) -> list[str]:
        if key not in index:
            index[key] = len(groups)
            groups.append((key, []))
        return groups[index[key]][1]

    for lineno, raw_line in enumerate(delta_lines, start=1):
        line = raw_line.strip()
        if not line:
            continue
        resolved = _resolve_insert(line, groups, lineno)
        if resolved is not None:
            moved_idx, sibling_idx, where = resolved
            if moved_idx == sibling_idx:
                raise DeltaError(
                    f"delta line {lineno}: insert cannot place a policy before/after itself"
                )
            sibling_key = groups[sibling_idx][0]
            moved = groups.pop(moved_idx)
            sibling_idx = next(i for i, (k, _l) in enumerate(groups) if k == sibling_key)
            dest = sibling_idx if where == "before" else sibling_idx + 1
            groups.insert(dest, moved)
            index = {key: i for i, (key, _lines) in enumerate(groups)}
            continue

        for verb in ("activate", "deactivate", "delete", "set"):
            if line.startswith(verb + " "):
                remainder = line[len(verb) + 1 :]
                break
        else:
            raise DeltaError(f"delta line {lineno}: unrecognized delta line")

        key = _policy_key_for_line(remainder)
        if key is None:
            raise DeltaError(f"delta line {lineno}: does not target a security policy")
        is_whole_policy = remainder.strip() == key

        if verb == "set":
            target = _group_for(key)
            full_line = f"set {remainder}"
            if full_line not in target:
                target.append(full_line)
        elif verb == "delete":
            if key not in index:
                raise DeltaError(f"delta line {lineno}: delete references unknown policy")
            if is_whole_policy:
                groups.pop(index[key])
                index = {k: i for i, (k, _l) in enumerate(groups)}
            else:
                target = groups[index[key]][1]
                prefix_plain = f"set {remainder}"
                prefix_inactive = f"inactive: set {remainder}"
                kept = [ln for ln in target if ln not in (prefix_plain, prefix_inactive)]
                if len(kept) == len(target):
                    raise DeltaError(
                        f"delta line {lineno}: sub-statement delete must exactly match one "
                        "existing statement in v1"
                    )
                groups[index[key]] = (key, kept)
        elif verb in ("activate", "deactivate"):
            if key not in index:
                raise DeltaError(f"delta line {lineno}: {verb} references unknown policy")
            if not is_whole_policy:
                raise DeltaError(
                    f"delta line {lineno}: sub-statement {verb} is not supported in v1 -- "
                    "only a whole policy can be activated/deactivated"
                )
            target_idx = index[key]
            new_lines = []
            for existing in groups[target_idx][1]:
                body = (
                    existing[len("inactive:") :].strip()
                    if existing.startswith("inactive:")
                    else existing
                )
                new_lines.append(f"inactive: {body}" if verb == "deactivate" else body)
            groups[target_idx] = (key, new_lines)

    return _flatten(groups)


def validate_security_policies_only(text: str) -> None:
    """Refuse any line outside a `security policies ...` stanza.

    The tool only ever asks the caller for
    `show configuration security policies | display set`. `current_text` is
    audited by the wrapper, so a caller who pastes a broader config dump
    instead must be rejected before any of that text reaches the evaluator
    or the audit trail, rather than silently dropping the unrecognized lines
    the way `_group_lines` does internally.
    """
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        body = line[len("inactive:") :].strip() if line.startswith("inactive:") else line
        if not body.startswith("set ") or _policy_key_for_line(body[len("set ") :]) is None:
            # The error message reports position only, never the offending
            # line's text: this text ends up verbatim in the ssdf.audit error
            # column (see services/mcp-query wrapper.py), and a caller who
            # pastes a broader config dump than requested may have sensitive
            # content on the unrelated lines.
            raise DeltaError(
                "junos_current_text must contain only 'security policies' set/inactive-set "
                f"lines (from 'show configuration security policies | display set'): "
                f"line {lineno} is not a 'security policies' statement"
            )


def apply_junos_text_delta(
    current_text: str, delta_lines: list[str], device_name: str, now: str
) -> tuple[list[dict], list[dict]]:
    """Return (P, P') for the Junos text-delta form: P from `current_text`
    as-is, P' from `current_text` with `delta_lines` applied."""
    validate_security_policies_only(current_text)
    p_rules = parse_security_policies(current_text, device_name, now)
    new_text = apply_junos_set_delta(current_text, delta_lines)
    p_prime_rules = parse_security_policies(new_text, device_name, now)
    return p_rules, p_prime_rules
