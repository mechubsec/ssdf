"""Per-tool authz + audit wrapper (M7a).

Wraps each registered tool so that, per call: (1) the caller principal +
allowed_tools are resolved, (2) per-tool authorization is enforced (deny ->
structured ``{"error": "forbidden"}``, audited), (3) the underlying tool runs
unchanged, (4) one audit row is recorded. ``functools.wraps`` preserves the
tool's signature + docstring so FastMCP builds the correct schema.
"""

from __future__ import annotations

import datetime as _dt
import functools
import hashlib
from typing import Any, Callable

from .attribution import current_attribution
from .auth import current_caller_claims
from .classification import classes_for_tool
from .ratelimit import ConcurrencyExceeded, PrincipalLimiter, RateLimitExceeded

# Args that must never reach ssdf.audit verbatim, by tool name:
# `change_impact.junos_current_text` is the caller's pasted device output,
# which may carry device secrets alongside the policy config. Hash + length
# round-trips the argument for correlation (same input -> same hash) without
# storing the secret-bearing text itself in the long-retention evidence tier.
REDACTED_ARGS: dict[str, frozenset[str]] = {
    "change_impact": frozenset({"junos_current_text"}),
}


def _hash_summary(value: str) -> dict:
    return {
        "sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
        "length": len(value),
    }


def _redact_for_audit(tool_name: str, kwargs: dict) -> dict:
    redact_keys = REDACTED_ARGS.get(tool_name)
    redacted = dict(kwargs) if redact_keys or tool_name == "change_impact" else kwargs
    for key in redact_keys or ():
        value = redacted.get(key)
        if isinstance(value, str) and value:
            redacted[key] = _hash_summary(value)
    if tool_name == "change_impact":
        # The Junos text-delta form's `delta["lines"]` is, like
        # `junos_current_text`, the caller's pasted material -- a rejected
        # line (not yet vetted against the security-policies allowlist) must
        # not reach ssdf.audit verbatim via `args` even though the rejection
        # itself is reported by line number only.
        delta = redacted.get("delta")
        if isinstance(delta, dict) and isinstance(delta.get("lines"), list):
            lines = delta["lines"]
            joined = "\n".join(str(line) for line in lines)
            redacted["delta"] = {**_hash_summary(joined), "line_count": len(lines)}
    return redacted


def row_count_of(result: Any) -> int:
    """Best-effort row count: explicit ``row_count``, else ``len(rows)``, else 0."""
    if isinstance(result, dict):
        explicit = result.get("row_count")
        if isinstance(explicit, int):
            return explicit
        rows = result.get("rows")
        if isinstance(rows, list):
            return len(rows)
    return 0


def audited_tool(
    tool_name: str,
    fn: Callable[..., Any],
    auditor: Any,
    *,
    tier: str = "sovereign",
    caller: Callable[[], tuple] = current_caller_claims,
    limiter: PrincipalLimiter | None = None,
    attribution: Callable[[], dict] = current_attribution,
) -> Callable[..., Any]:
    """Return ``fn`` wrapped with per-call authz + audit for ``tool_name``.

    ``caller`` may return ``(principal, allowed_tools)`` (legacy) or
    ``(principal, allowed_tools, not_after)``; an expired ``not_after`` is
    denied exactly like a disallowed tool (M2 token expiry).

    ``limiter`` applies per-principal rate and concurrency limits (issue #8).
    It is checked AFTER authorization: a principal that may not call a tool
    should be told that, not have its refusal attributed to load. A limited
    call is audited as a deny like any other, so "was it throttled" is a
    question ``ssdf.audit`` can answer.
    """
    data_classes = sorted(classes_for_tool(tool_name))

    def _deny(principal: str, kwargs: dict, detail: str, error: str = "forbidden") -> dict:
        auditor.record(
            principal=principal,
            tier=tier,
            tool=tool_name,
            args=_redact_for_audit(tool_name, kwargs),
            data_classes=data_classes,
            decision="deny",
            row_count=0,
            error=error,
            **attribution(),
        )
        return {"error": error, "detail": detail}

    @functools.wraps(fn)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        # FastMCP dispatches tools by keyword, so the audited args are kwargs.
        # If a caller ever invokes positionally, those args run but aren't recorded.
        info = caller()
        principal, allowed = info[0], info[1]
        not_after = info[2] if len(info) > 2 else None
        if not_after is not None and _dt.datetime.now(_dt.timezone.utc) >= not_after:
            return _deny(principal, kwargs, f"token for principal '{principal}' has expired")
        if allowed is not None and tool_name not in allowed:
            return _deny(
                principal, kwargs, f"tool '{tool_name}' not permitted for principal '{principal}'"
            )
        if limiter is not None and limiter.enabled:
            try:
                limiter.acquire(principal)
            except (RateLimitExceeded, ConcurrencyExceeded) as exc:
                # A distinct error code from "forbidden": throttling is
                # transient and the caller should retry, where an authz denial
                # never will succeed. Conflating them tells an agent to give up
                # on a tool it is entitled to use.
                return _deny(principal, kwargs, str(exc), error="rate_limited")

        # M16f: the audit row is written in `finally` so a tool that raises is
        # still recorded -- it used to skip the audit entirely, because the
        # record() call below the try/except never ran once an exception
        # propagated past it. The exception itself still propagates (FastMCP's
        # mask_error_details keeps its detail from reaching the model); only
        # the audit write is unconditional.
        result: Any = None
        error = ""
        try:
            result = fn(*args, **kwargs)
            error = result.get("error", "") if isinstance(result, dict) else ""
            return result
        except BaseException as exc:  # noqa: BLE001 - audited below, then re-raised
            # str(exc) is "" for a message-less exception (e.g. raise
            # TimeoutError()), which would record as a clean allow with no
            # error -- indistinguishable from success. Bare `Exception` also
            # let a BaseException (e.g. KeyboardInterrupt/SystemExit) skip the
            # audit write entirely, since it isn't caught here at all.
            error = f"{type(exc).__name__}: {exc}"
            raise
        finally:
            if limiter is not None and limiter.enabled:
                # Release even when the tool raises, or one failing call would
                # permanently consume a concurrency slot.
                limiter.release(principal)
            auditor.record(
                principal=principal,
                tier=tier,
                tool=tool_name,
                args=_redact_for_audit(tool_name, kwargs),
                data_classes=data_classes,
                decision="allow",
                row_count=row_count_of(result) if isinstance(result, dict) else 0,
                error=error,
                **attribution(),
            )

    return wrapped
