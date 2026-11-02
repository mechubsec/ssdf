"""Runtime reader of the caller principal from the FastMCP access-token claims (M7a).

Edge hardening (M2): claims may carry a ``not_after`` ISO-8601 expiry put there
by ``server.build_app`` from the tokens file; ``current_caller_claims`` surfaces
it so the per-call wrapper can deny expired tokens.
"""

from __future__ import annotations

import datetime as _dt

from fastmcp.server.dependencies import get_access_token

# Sentinel for a malformed not_after claim: always in the past, so the token
# reads as expired (fail closed) rather than as never-expiring.
_EXPIRED = _dt.datetime(1970, 1, 1, tzinfo=_dt.timezone.utc)


def _parse_claim_not_after(value: object) -> _dt.datetime | None:
    """Parse the ``not_after`` claim; naive ⇒ UTC; malformed ⇒ already expired."""
    if value is None:
        return None
    try:
        parsed = _dt.datetime.fromisoformat(str(value))
    except ValueError:
        return _EXPIRED
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_dt.timezone.utc)
    return parsed


def current_caller_claims() -> tuple[str, frozenset[str] | None, _dt.datetime | None]:
    """Return ``(principal, allowed_tools, not_after)`` for the in-flight request.

    ``allowed_tools`` is ``None`` when the token grants all tools; ``not_after``
    is ``None`` when the token never expires. Falls back to ``sub`` then
    ``"unknown"`` when ``principal`` is absent.
    """
    token = get_access_token()
    claims = token.claims if token is not None and token.claims else {}
    principal = claims.get("principal") or claims.get("sub") or "unknown"
    allowed = claims.get("allowed_tools")
    allowed_set = None if allowed is None else frozenset(allowed)
    return principal, allowed_set, _parse_claim_not_after(claims.get("not_after"))


def current_caller_identity() -> dict:
    """Return the in-flight caller's own token metadata (the ``whoami`` payload).

    Built from an explicit field list, never from the raw claims, so nothing
    else a claim might carry (allowed_tools, digests) can leak into the output.
    """
    token = get_access_token()
    claims = token.claims if token is not None and token.claims else {}
    expires = _parse_claim_not_after(claims.get("not_after"))
    return {
        "principal": claims.get("principal") or claims.get("sub") or "unknown",
        "created_at": claims.get("created_at"),
        "expires_at": expires.isoformat() if expires is not None else None,
        "local_only": bool(claims.get("local_only", False)),
    }


def current_caller() -> tuple[str, frozenset[str] | None]:
    """Return ``(principal, allowed_tools)`` for the in-flight request.

    Backward-compatible accessor; prefer ``current_caller_claims`` for expiry.
    """
    principal, allowed_set, _ = current_caller_claims()
    return principal, allowed_set
