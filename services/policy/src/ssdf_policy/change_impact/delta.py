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

OpKind = Literal["add", "modify", "delete", "move", "enable", "disable"]


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


def parse_json_delta(ops: list[dict]) -> Delta:
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


def apply_delta(rules: list[dict], delta: Delta) -> list[dict]:
    """P' = apply(P, Delta) for the JSON-op form. Pure: `rules` is not mutated."""
    result = copy.deepcopy(rules)
    for op in delta.ops:
        if op.kind == "add":
            new_rule = copy.deepcopy(op.rule)
            new_rule.setdefault("enabled", True)
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
            result[idx].update(copy.deepcopy(op.fields))
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
    return result


# ---------------------------------------------------------------------------
# Junos `| display set` text delta (form b)
# ---------------------------------------------------------------------------

_POLICY_PREFIX_RE = re.compile(
    r"^(security policies from-zone \S+ to-zone \S+ policy \S+|security policies global policy \S+)"
)
_INSERT_RE = re.compile(r"^insert\s+(\S+)\s+(before|after)\s+(\S+)\s*$")


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


def apply_junos_set_delta(current_text: str, delta_lines: list[str]) -> str:
    """Apply `set`/`delete`/`insert ... before|after`/`activate`/`deactivate`
    lines to `current_text` (the current `| display set` output) and return
    the resulting display-set text. The caller re-parses it with
    `parse_security_policies` to get P'.
    """
    groups = _group_lines(current_text)
    index = {key: i for i, (key, _lines) in enumerate(groups)}

    def _group_for(key: str) -> list[str]:
        if key not in index:
            index[key] = len(groups)
            groups.append((key, []))
        return groups[index[key]][1]

    for raw_line in delta_lines:
        line = raw_line.strip()
        if not line:
            continue
        insert_match = _INSERT_RE.match(line)
        if insert_match:
            name, where, sibling = insert_match.groups()
            moved_idx = next(
                (i for i, (k, _l) in enumerate(groups) if k.endswith(f"policy {name}")), None
            )
            sibling_idx = next(
                (i for i, (k, _l) in enumerate(groups) if k.endswith(f"policy {sibling}")), None
            )
            if moved_idx is None or sibling_idx is None:
                raise DeltaError(f"insert references unknown policy: {line!r}")
            moved = groups.pop(moved_idx)
            if sibling_idx > moved_idx:
                sibling_idx -= 1
            sibling_idx = next(
                i for i, (k, _l) in enumerate(groups) if k.endswith(f"policy {sibling}")
            )
            dest = sibling_idx if where == "before" else sibling_idx + 1
            groups.insert(dest, moved)
            index = {key: i for i, (key, _lines) in enumerate(groups)}
            continue

        for verb in ("activate", "deactivate", "delete", "set"):
            if line.startswith(verb + " "):
                remainder = line[len(verb) + 1 :]
                break
        else:
            raise DeltaError(f"unrecognized delta line: {line!r}")

        key = _policy_key_for_line(remainder)
        if key is None:
            raise DeltaError(f"delta line does not target a security policy: {line!r}")
        is_whole_policy = remainder.strip() == key

        if verb == "set":
            target = _group_for(key)
            full_line = f"set {remainder}"
            if full_line not in target:
                target.append(full_line)
        elif verb == "delete":
            if key not in index:
                continue
            if is_whole_policy:
                groups.pop(index[key])
                index = {k: i for i, (k, _l) in enumerate(groups)}
            else:
                target = groups[index[key]][1]
                prefix_plain = f"set {remainder}"
                prefix_inactive = f"inactive: set {remainder}"
                groups[index[key]] = (
                    key,
                    [ln for ln in target if ln not in (prefix_plain, prefix_inactive)],
                )
        elif verb in ("activate", "deactivate"):
            if key not in index:
                raise DeltaError(f"{verb} references unknown policy: {line!r}")
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


def apply_junos_text_delta(
    current_text: str, delta_lines: list[str], device_name: str, now: str
) -> tuple[list[dict], list[dict]]:
    """Return (P, P') for the Junos text-delta form: P from `current_text`
    as-is, P' from `current_text` with `delta_lines` applied."""
    p_rules = parse_security_policies(current_text, device_name, now)
    new_text = apply_junos_set_delta(current_text, delta_lines)
    p_prime_rules = parse_security_policies(new_text, device_name, now)
    return p_rules, p_prime_rules
