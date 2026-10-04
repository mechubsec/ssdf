"""Typed wrapper for untrusted, log-derived free text (MEC-568).

Fields like an IPS/IDS signature name or a raw `ext` value come from traffic
a sensor observed, not from the operator's own configuration -- an attacker
who controls the traffic a device logs also controls substrings of what gets
written there (a crafted DNS query name, a crafted HTTP Host header, a
crafted alert signature). Carrying that text as plain `str` makes it
indistinguishable, at the type level, from operator/system text such as a
configured rule name or a zone name.

`UntrustedText` is the boundary type: raw log/alert text is converted here,
once, where it is read off the ClickHouse row, and nothing downstream may
reach for a bare `str` at that call site without going through
`from_raw()`. It is a data container only -- it caps length deterministically
and never executes, interprets, or templates its contents. The capped value
still goes into the tool's JSON response (an LLM-backed tool like
`explain_rule` or `explain_access` summarizes it), but every untrusted field
in that response carries its `truncated` flag alongside it, so truncation is
visible to the caller rather than a silent cut.
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
        """JSON-safe shape for a tool response: value + explicit truncation flag."""
        return {"value": self.value, "truncated": self.truncated}
