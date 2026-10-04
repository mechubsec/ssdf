"""Runtime configuration loaded from environment + token file."""

from __future__ import annotations

import datetime as _dt
import json
import os
from dataclasses import dataclass
from pathlib import Path

from .tokenstore import (
    InsecureTokenFileError,
    assert_file_mode_private,
    digest_for,
    normalize_token_keys,
    warn_about_legacy_tokens,
)

from ssdf_common.config import ConfigError, Secret, require_tls_or_loopback


@dataclass(frozen=True)
class TokenPrincipal:
    """A bearer token's identity. ``allowed_tools=None`` means all tools allowed.

    ``not_after=None`` means the token never expires; otherwise it is a
    timezone-aware UTC datetime after which the token is denied per call.

    ``local_only`` is the token-holder's attestation that it drives a model
    running on infrastructure the operator controls (M16e). It defaults to
    ``False`` (fail closed): a token file entry that never mentions it is
    treated as unattested and cannot authenticate against a ``tier="sovereign"``
    build, regardless of what the caller claims elsewhere.
    """

    principal: str
    allowed_tools: frozenset[str] | None
    not_after: _dt.datetime | None = None
    local_only: bool = False


@dataclass(frozen=True)
class Config:
    ch_host: str
    ch_port: int
    ch_user: str
    ch_password: Secret
    ch_database: str
    mcp_bind: str
    mcp_port: int
    tokens: dict[str, "TokenPrincipal"]
    ch_audit_user: str = "ssdf_audit"
    ch_audit_password: Secret | None = None
    ch_audit_verify_password: Secret | None = None
    # MEC-565: path to the base64-encoded Ed25519 verifying key for
    # ssdf.audit chain checkpoints (checkpoint_verify.load_verifying_key).
    # None disables checkpoint-based verification; verify_audit.py then falls
    # back to today's behaviour (an expired genesis reports every surviving
    # row in that chain as unreachable, same as before this feature existed).
    ch_checkpoint_verify_key_path: str | None = None
    # M16f: default False preserves the existing (best-effort) deploy; set
    # MCP_AUDIT_REQUIRED=1 to refuse startup rather than silently run with
    # audit disabled when CH_AUDIT_PASSWORD is unset.
    audit_required: bool = False
    max_execution_time: int = 10
    max_result_rows: int = 100000
    max_memory_usage: int = 1_000_000_000
    ch_secure: bool = False
    ch_ca_file: str | None = None
    # Per-principal limits (issue #8). 0 disables, which is the default:
    # an unconfigured deployment behaves exactly as it did before.
    max_calls_per_minute: int = 0
    max_concurrent_calls: int = 0


def ch_tls_kwargs(config: "Config") -> dict:
    """Extra ``clickhouse_connect.get_client`` kwargs for TLS (empty when off).

    When ``ch_secure`` is set, connect over HTTPS; ``ca_cert`` is passed only
    when ``ch_ca_file`` is configured (self-signed local CA per the L1 design).

    Raises ConfigError for a plaintext connection to a non-loopback host — the
    password would otherwise cross the wire in the clear.
    """
    require_tls_or_loopback(config.ch_host, config.ch_secure)
    if not config.ch_secure:
        return {}
    kwargs: dict = {"interface": "https"}
    if config.ch_ca_file:
        kwargs["ca_cert"] = config.ch_ca_file
    return kwargs


def parse_not_after(value: object) -> _dt.datetime | None:
    """Parse a tokens-file ``not_after`` ISO-8601 string (naive ⇒ UTC).

    Raises ``ConfigError`` on any non-string or unparseable value (fail closed).
    """
    if value is None:
        return None
    if not isinstance(value, str):
        raise ConfigError(f"not_after must be an ISO-8601 string, got {type(value).__name__}")
    try:
        parsed = _dt.datetime.fromisoformat(value)
    except ValueError as exc:
        raise ConfigError(f"invalid not_after {value!r}: {exc}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=_dt.timezone.utc)
    return parsed


def parse_local_only(value: object) -> bool:
    """Parse a tokens-file ``local_only`` flag. Absent ⇒ False (fail closed)."""
    if value is None:
        return False
    if not isinstance(value, bool):
        raise ConfigError(f"local_only must be a boolean, got {type(value).__name__}")
    return value


def _read_token() -> str:
    inline = os.environ.get("MCP_AUTH_TOKEN")
    if inline:
        token = inline.strip()
        if not token:
            raise ConfigError("auth token is empty")
        return token
    token_file = os.environ.get("MCP_TOKEN_FILE")
    if token_file and Path(token_file).is_file():
        token = Path(token_file).read_text(encoding="utf-8").strip()
        if not token:
            raise ConfigError("auth token is empty")
        return token
    raise ConfigError("no bearer token: set MCP_AUTH_TOKEN or MCP_TOKEN_FILE")


def load_token_map() -> dict[str, TokenPrincipal]:
    """Load the multi-principal token map (env ``MCP_TOKENS_FILE``).

    Falls back to the single-token path (``MCP_AUTH_TOKEN``/``MCP_TOKEN_FILE``)
    mapped to principal ``agent`` with all tools allowed, preserving the existing
    deploy. Raises ``ConfigError`` if neither is configured (fail closed).
    """
    tokens_file = os.environ.get("MCP_TOKENS_FILE")
    if not tokens_file:
        # Single-token path: the secret arrives by env or a file of its own, so
        # there is no map to key by digest. Hash it here anyway, so every code
        # path downstream deals in digests only.
        single = _read_token()
        local_only = os.environ.get("MCP_AUTH_TOKEN_LOCAL_ONLY", "").strip().lower() in (
            "1",
            "true",
        )
        return {
            digest_for(single): TokenPrincipal(
                principal="agent", allowed_tools=None, local_only=local_only
            )
        }
    path = Path(tokens_file)
    if not path.is_file():
        raise ConfigError(f"MCP_TOKENS_FILE not found: {tokens_file}")
    try:
        assert_file_mode_private(path)
    except InsecureTokenFileError as exc:
        raise ConfigError(str(exc)) from exc
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"invalid token map JSON: {exc}") from exc
    if not isinstance(data, dict) or not data:
        raise ConfigError("token map must be a non-empty JSON object")
    for token, meta in data.items():
        if not token or not isinstance(meta, dict):
            raise ConfigError("each token must map to an object with a 'principal'")
        if not meta.get("principal"):
            raise ConfigError("token entry missing 'principal'")
    try:
        by_digest, legacy = normalize_token_keys(data, tokens_file)
    except ValueError as exc:
        raise ConfigError(str(exc)) from exc
    warn_about_legacy_tokens(legacy, tokens_file)

    tokens: dict[str, TokenPrincipal] = {}
    for token_digest, meta in by_digest.items():
        allowed = meta.get("allowed_tools")
        allowed_set = None if allowed is None else frozenset(allowed)
        tokens[token_digest] = TokenPrincipal(
            principal=meta["principal"],
            allowed_tools=allowed_set,
            not_after=parse_not_after(meta.get("not_after")),
            local_only=parse_local_only(meta.get("local_only")),
        )
    return tokens


def load_config() -> Config:
    password = os.environ.get("CH_PASSWORD")
    if password is None:
        raise ConfigError("CH_PASSWORD is required")
    audit_password = os.environ.get("CH_AUDIT_PASSWORD")
    audit_verify_password = os.environ.get("CH_AUDIT_VERIFY_PASSWORD")
    return Config(
        ch_host=os.environ.get("CH_HOST", "127.0.0.1"),
        ch_port=int(os.environ.get("CH_PORT", "8123")),
        ch_user=os.environ.get("CH_USER", "ssdf_ro"),
        ch_password=Secret(password),
        ch_database=os.environ.get("CH_DATABASE", "ssdf"),
        mcp_bind=os.environ.get("MCP_BIND", "0.0.0.0"),
        mcp_port=int(os.environ.get("MCP_PORT", "30032")),
        tokens=load_token_map(),
        ch_audit_user=os.environ.get("CH_AUDIT_USER", "ssdf_audit"),
        ch_audit_password=Secret(audit_password) if audit_password else None,
        ch_audit_verify_password=Secret(audit_verify_password) if audit_verify_password else None,
        ch_checkpoint_verify_key_path=os.environ.get("CH_CHECKPOINT_VERIFY_KEY_PATH") or None,
        audit_required=os.environ.get("MCP_AUDIT_REQUIRED", "").strip().lower() in ("1", "true"),
        max_execution_time=int(os.environ.get("MCP_MAX_EXEC_SECS", "10")),
        max_result_rows=int(os.environ.get("MCP_MAX_RESULT_ROWS", "100000")),
        max_memory_usage=int(os.environ.get("MCP_MAX_MEMORY_BYTES", "1000000000")),
        ch_secure=os.environ.get("CH_SECURE", "").strip().lower() in ("1", "true"),
        ch_ca_file=os.environ.get("CH_CA_FILE") or None,
        max_calls_per_minute=int(os.environ.get("MCP_MAX_CALLS_PER_MINUTE", "0")),
        max_concurrent_calls=int(os.environ.get("MCP_MAX_CONCURRENT_CALLS", "0")),
    )
