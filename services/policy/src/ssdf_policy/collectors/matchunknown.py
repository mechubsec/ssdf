"""Shared `match_unknown` derivation for Junos and PAN-OS rule dicts.

The configured-policy collectors (`junos.py`, `panos.py`) and
`change_impact.delta.apply_delta` (which can introduce or remove the same
clauses via `add`/`modify`) must agree on this determination, so it lives in
one place rather than two copies that can drift apart.
"""

from __future__ import annotations

_JUNOS_UNRESOLVED_MATCH_FIELDS = (
    "source_identity",
    "dynamic_application",
    "url_category",
    "source_end_user_profile",
)


def _restricts(members: list[str]) -> bool:
    """True if a member list narrows the match beyond "no restriction"."""
    return members not in ([], ["any"])


def derive_match_unknown(rule: dict, provider: str) -> bool:
    """Whether `rule`'s own clauses (ignoring anything the caller already
    flagged) require `match_unknown`, per vendor."""
    if provider == "juniper":
        return bool(
            any(rule.get(field) for field in _JUNOS_UNRESOLVED_MATCH_FIELDS)
            or rule.get("scheduler_name")
        )
    if provider == "paloalto":
        return bool(
            rule.get("schedule")
            or _restricts(rule.get("source_user") or [])
            or _restricts(rule.get("url_category") or [])
            or _restricts(rule.get("source_hip") or [])
            or _restricts(rule.get("destination_hip") or [])
        )
    raise ValueError(f"unsupported provider: {provider!r}")
