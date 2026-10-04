# tests/test_untrusted_text.py
"""UntrustedText: the type-level boundary for log-derived free text (MEC-568)."""

import os

os.environ.setdefault("CH_PASSWORD", "x")
os.environ.setdefault("MCP_AUTH_TOKEN", "t")

from ssdf_mcp_query.untrusted_text import DEFAULT_MAX_LEN, UntrustedText


def test_short_value_is_not_truncated():
    wrapped = UntrustedText.from_raw("ET POLICY Suspicious TLS")
    assert wrapped.value == "ET POLICY Suspicious TLS"
    assert wrapped.truncated is False
    assert wrapped.to_response() == {
        "value": "ET POLICY Suspicious TLS",
        "truncated": False,
        "untrusted": True,
    }


def test_none_becomes_empty_untruncated_string():
    wrapped = UntrustedText.from_raw(None)
    assert wrapped.value == ""
    assert wrapped.truncated is False


def test_oversized_value_is_capped_and_flagged():
    raw = "A" * (DEFAULT_MAX_LEN + 100)
    wrapped = UntrustedText.from_raw(raw)
    assert len(wrapped.value) == DEFAULT_MAX_LEN
    assert wrapped.truncated is True
    # Truncation must be visible in the serialized shape, never a silent cut.
    assert wrapped.to_response()["truncated"] is True


def test_non_string_scalar_is_coerced_not_rejected():
    # Driver-returned scalars (ints, etc.) must not blow up the boundary.
    wrapped = UntrustedText.from_raw(12345)
    assert wrapped.value == "12345"
    assert wrapped.truncated is False


def test_custom_max_len_respected():
    wrapped = UntrustedText.from_raw("abcdefghij", max_len=5)
    assert wrapped.value == "abcde"
    assert wrapped.truncated is True


def test_is_a_distinct_type_from_str():
    wrapped = UntrustedText.from_raw("hello")
    assert not isinstance(wrapped, str)
    assert isinstance(wrapped.value, str)
