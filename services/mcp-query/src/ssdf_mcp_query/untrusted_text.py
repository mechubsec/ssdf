"""Typed wrapper for untrusted, log-derived free text.

Text sourced from observed traffic is distinct, at the type level, from
operator/system-configured text: carrying both as plain `str` makes that
distinction invisible to callers. `UntrustedText` is the boundary type: raw
values are converted here, once, where they are read off the data store, and
nothing downstream reaches for a bare `str` at that call site without going
through `from_raw()`.

It is a data container only -- it caps length deterministically and never
executes, interprets, or templates its contents. The response shape carries
an explicit `untrusted` marker alongside the value and its `truncated` flag,
so a consumer of the tool output can tell this field apart from a trusted
one without re-deriving that from context.
"""

from __future__ import annotations

from dataclasses import dataclass

# Generous enough for a real signature/ext value, small enough that a
# multi-kilobyte crafted payload (e.g. a stuffed DNS TXT record relayed into
# a log field) can't balloon a tool response or a downstream prompt.
DEFAULT_MAX_LEN = 512


@dataclass(frozen=True)
class UntrustedText:
    """A length-capped, log-derived string, distinct from trusted `str` fields."""

    value: str
    truncated: bool

    @classmethod
    def from_raw(cls, raw: object, max_len: int = DEFAULT_MAX_LEN) -> "UntrustedText":
        """Convert a raw log/ext value at the boundary. `raw` may be None, str, or any
        scalar the ClickHouse driver handed back; it is never trusted to already be a
        well-formed, bounded string."""
        text = "" if raw is None else str(raw)
        if len(text) > max_len:
            return cls(value=text[:max_len], truncated=True)
        return cls(value=text, truncated=False)

    def to_response(self) -> dict:
        """JSON-safe shape for a tool response: value, truncation flag, and an
        explicit `untrusted` marker so the label survives JSON serialization
        instead of ending at the type boundary."""
        return {"value": self.value, "truncated": self.truncated, "untrusted": True}
