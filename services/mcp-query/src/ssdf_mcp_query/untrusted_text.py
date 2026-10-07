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

import unicodedata
from dataclasses import dataclass

# Bounds response size for oversized values.
DEFAULT_MAX_LEN = 512

# Unicode categories stripped at the boundary: controls (Cc), format
# characters (Cf), line/paragraph separators (Zl/Zp), and private-use /
# surrogate / unassigned code points (Co/Cs/Cn). Variation selectors are
# category Mn, so they are listed explicitly. Category-based rather than a
# range list, so newly assigned invisible characters are covered too.
_STRIP_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp", "Co", "Cs", "Cn"})


def _is_stripped(ch: str) -> bool:
    cp = ord(ch)
    if 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF:
        return True
    return unicodedata.category(ch) in _STRIP_CATEGORIES


def _strip_controls(text: str) -> str:
    return "".join(ch for ch in text if not _is_stripped(ch))


@dataclass(frozen=True)
class UntrustedText:
    """A length-capped, log-derived string, distinct from trusted `str` fields."""

    value: str
    truncated: bool

    @classmethod
    def from_raw(cls, raw: object, max_len: int = DEFAULT_MAX_LEN) -> "UntrustedText":
        """Convert a raw log/ext value at the boundary. `raw` may be None, str, or any
        scalar the ClickHouse driver handed back; it is never trusted to already be a
        well-formed, bounded string. Control characters are stripped before the length
        cap is applied, so a long run of stripped bytes cannot itself push otherwise-kept
        text out past `max_len`."""
        text = "" if raw is None else str(raw)
        text = _strip_controls(text)
        if len(text) > max_len:
            return cls(value=text[:max_len], truncated=True)
        return cls(value=text, truncated=False)

    def to_response(self) -> dict:
        """JSON-safe shape for a tool response: value, truncation flag, and an
        explicit `untrusted` marker so the label survives JSON serialization
        instead of ending at the type boundary."""
        return {"value": self.value, "truncated": self.truncated, "untrusted": True}
