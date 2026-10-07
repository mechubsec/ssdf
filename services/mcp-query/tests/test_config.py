import json
import pathlib
import pytest
from ssdf_mcp_query.config import load_config, load_token_map, ConfigError
from ssdf_mcp_query.tokenstore import digest_for


def test_single_token_fallback_from_file(monkeypatch, tmp_path):
    token_file = tmp_path / "token"
    token_file.write_text("secret-token\n")
    monkeypatch.setenv("CH_HOST", "10.64.0.9")
    monkeypatch.setenv("CH_USER", "ssdf_ro")
    monkeypatch.setenv("CH_PASSWORD", "pw")
    monkeypatch.setenv("MCP_TOKEN_FILE", str(token_file))
    monkeypatch.delenv("MCP_AUTH_TOKEN", raising=False)
    monkeypatch.delenv("MCP_TOKENS_FILE", raising=False)
    cfg = load_config()
    assert cfg.ch_host == "10.64.0.9"
    assert cfg.mcp_port == 30032
    # Keyed by digest: even the single-token path never keeps the secret.
    assert set(cfg.tokens) == {digest_for("secret-token")}
    principal = cfg.tokens[digest_for("secret-token")]
    assert principal.principal == "agent"
    assert principal.allowed_tools is None


def test_inline_token_env_wins(monkeypatch):
    monkeypatch.setenv("CH_PASSWORD", "pw")
    monkeypatch.setenv("MCP_AUTH_TOKEN", "inline")
    monkeypatch.delenv("MCP_TOKEN_FILE", raising=False)
    monkeypatch.delenv("MCP_TOKENS_FILE", raising=False)
    cfg = load_config()
    assert set(cfg.tokens) == {digest_for("inline")}
    assert cfg.tokens[digest_for("inline")].principal == "agent"


def test_missing_token_raises(monkeypatch):
    monkeypatch.setenv("CH_PASSWORD", "pw")
    monkeypatch.delenv("MCP_AUTH_TOKEN", raising=False)
    monkeypatch.delenv("MCP_TOKEN_FILE", raising=False)
    monkeypatch.delenv("MCP_TOKENS_FILE", raising=False)
    with pytest.raises(ConfigError):
        load_config()


def _write_tokens(tmp_path, payload) -> pathlib.Path:
    """Write a token file the loader will accept: owner-only, like the real one."""
    f = tmp_path / "tokens.json"
    f.write_text(json.dumps(payload))
    f.chmod(0o600)
    return f


def test_token_map_multi_principal(monkeypatch, tmp_path):
    f = _write_tokens(
        tmp_path,
        {
            digest_for("tok-triage"): {
                "principal": "triage-agent",
                "allowed_tools": ["query_flows", "top_talkers"],
            },
            digest_for("tok-admin"): {"principal": "admin-agent"},
        },
    )
    monkeypatch.setenv("MCP_TOKENS_FILE", str(f))
    tokens = load_token_map()
    assert tokens[digest_for("tok-triage")].principal == "triage-agent"
    assert tokens[digest_for("tok-triage")].allowed_tools == frozenset(
        {"query_flows", "top_talkers"}
    )
    assert tokens[digest_for("tok-admin")].allowed_tools is None


def test_token_map_empty_object_raises(monkeypatch, tmp_path):
    f = _write_tokens(tmp_path, {})
    monkeypatch.setenv("MCP_TOKENS_FILE", str(f))
    with pytest.raises(ConfigError):
        load_token_map()


def test_token_map_entry_missing_principal_raises(monkeypatch, tmp_path):
    f = tmp_path / "tokens.json"
    f.write_text(json.dumps({"tok": {"allowed_tools": ["query_flows"]}}))
    monkeypatch.setenv("MCP_TOKENS_FILE", str(f))
    with pytest.raises(ConfigError):
        load_token_map()


def test_audit_conn_fields(monkeypatch):
    monkeypatch.setenv("CH_PASSWORD", "pw")
    monkeypatch.setenv("MCP_AUTH_TOKEN", "inline")
    monkeypatch.setenv("CH_AUDIT_PASSWORD", "apw")
    monkeypatch.delenv("MCP_TOKENS_FILE", raising=False)
    monkeypatch.delenv("MCP_TOKEN_FILE", raising=False)
    cfg = load_config()
    assert cfg.ch_audit_user == "ssdf_audit"
    assert cfg.ch_audit_password.get() == "apw"


def test_audit_passwords_do_not_leak_via_repr(monkeypatch):
    monkeypatch.setenv("CH_PASSWORD", "pw")
    monkeypatch.setenv("MCP_AUTH_TOKEN", "inline")
    monkeypatch.setenv("CH_AUDIT_PASSWORD", "FAKEaudit")
    monkeypatch.setenv("CH_AUDIT_VERIFY_PASSWORD", "FAKEverify")
    monkeypatch.delenv("MCP_TOKENS_FILE", raising=False)
    monkeypatch.delenv("MCP_TOKEN_FILE", raising=False)
    cfg = load_config()
    assert "FAKEaudit" not in repr(cfg)
    assert "FAKEverify" not in repr(cfg)


def test_load_config_reads_query_limit_envs(monkeypatch):
    from ssdf_mcp_query.config import load_config

    monkeypatch.setenv("CH_PASSWORD", "x")
    monkeypatch.setenv("MCP_AUTH_TOKEN", "t")
    monkeypatch.setenv("MCP_MAX_RESULT_ROWS", "5")
    monkeypatch.setenv("MCP_MAX_MEMORY_BYTES", "9")
    cfg = load_config()
    assert cfg.max_result_rows == 5
    assert cfg.max_memory_usage == 9


def test_token_map_not_after_parsed_utc(monkeypatch, tmp_path):
    import datetime as dt

    f = _write_tokens(
        tmp_path,
        {
            digest_for("tok-exp"): {"principal": "p", "not_after": "2026-09-09T12:00:00+00:00"},
            digest_for("tok-naive"): {"principal": "q", "not_after": "2026-09-09T12:00:00"},
            digest_for("tok-forever"): {"principal": "r"},
        },
    )
    monkeypatch.setenv("MCP_TOKENS_FILE", str(f))
    tokens = load_token_map()
    expected = dt.datetime(2026, 9, 9, 12, 0, 0, tzinfo=dt.timezone.utc)
    assert tokens[digest_for("tok-exp")].not_after == expected
    # naive ISO strings are treated as UTC
    assert tokens[digest_for("tok-naive")].not_after == expected
    assert tokens[digest_for("tok-forever")].not_after is None


def test_token_map_bad_not_after_raises(monkeypatch, tmp_path):
    f = tmp_path / "tokens.json"
    f.write_text(json.dumps({"tok": {"principal": "p", "not_after": "next tuesday"}}))
    monkeypatch.setenv("MCP_TOKENS_FILE", str(f))
    with pytest.raises(ConfigError):
        load_token_map()


def test_token_map_non_string_not_after_raises(monkeypatch, tmp_path):
    f = tmp_path / "tokens.json"
    f.write_text(json.dumps({"tok": {"principal": "p", "not_after": 12345}}))
    monkeypatch.setenv("MCP_TOKENS_FILE", str(f))
    with pytest.raises(ConfigError):
        load_token_map()


def test_token_map_local_only_defaults_false(monkeypatch, tmp_path):
    f = _write_tokens(tmp_path, {digest_for("tok"): {"principal": "p"}})
    monkeypatch.setenv("MCP_TOKENS_FILE", str(f))
    tokens = load_token_map()
    assert tokens[digest_for("tok")].local_only is False


def test_token_map_local_only_true(monkeypatch, tmp_path):
    f = _write_tokens(tmp_path, {digest_for("tok"): {"principal": "p", "local_only": True}})
    monkeypatch.setenv("MCP_TOKENS_FILE", str(f))
    tokens = load_token_map()
    assert tokens[digest_for("tok")].local_only is True


def test_token_map_local_only_wrong_type_raises(monkeypatch, tmp_path):
    f = tmp_path / "tokens.json"
    f.write_text(json.dumps({"tok": {"principal": "p", "local_only": "yes"}}))
    monkeypatch.setenv("MCP_TOKENS_FILE", str(f))
    with pytest.raises(ConfigError):
        load_token_map()


def test_single_token_fallback_local_only_env(monkeypatch, tmp_path):
    token_file = tmp_path / "token"
    token_file.write_text("secret-token\n")
    monkeypatch.setenv("CH_PASSWORD", "pw")
    monkeypatch.setenv("MCP_TOKEN_FILE", str(token_file))
    monkeypatch.delenv("MCP_AUTH_TOKEN", raising=False)
    monkeypatch.delenv("MCP_TOKENS_FILE", raising=False)
    monkeypatch.delenv("MCP_AUTH_TOKEN_LOCAL_ONLY", raising=False)
    assert load_config().tokens[digest_for("secret-token")].local_only is False
    monkeypatch.setenv("MCP_AUTH_TOKEN_LOCAL_ONLY", "true")
    assert load_config().tokens[digest_for("secret-token")].local_only is True


def test_ch_secure_env_parsing(monkeypatch):
    monkeypatch.setenv("CH_PASSWORD", "x")
    monkeypatch.setenv("MCP_AUTH_TOKEN", "t")
    monkeypatch.delenv("CH_SECURE", raising=False)
    monkeypatch.delenv("CH_CA_FILE", raising=False)
    cfg = load_config()
    assert cfg.ch_secure is False
    assert cfg.ch_ca_file is None
    monkeypatch.setenv("CH_SECURE", "1")
    monkeypatch.setenv("CH_CA_FILE", "/etc/ssdf/ssdf-ca.crt")
    cfg = load_config()
    assert cfg.ch_secure is True
    assert cfg.ch_ca_file == "/etc/ssdf/ssdf-ca.crt"
    monkeypatch.setenv("CH_SECURE", "true")
    assert load_config().ch_secure is True
    monkeypatch.setenv("CH_SECURE", "0")
    assert load_config().ch_secure is False


def test_audit_required_env_parsing(monkeypatch):
    monkeypatch.setenv("CH_PASSWORD", "x")
    monkeypatch.setenv("MCP_AUTH_TOKEN", "t")
    monkeypatch.delenv("MCP_AUDIT_REQUIRED", raising=False)
    assert load_config().audit_required is False
    monkeypatch.setenv("MCP_AUDIT_REQUIRED", "1")
    assert load_config().audit_required is True
    monkeypatch.setenv("MCP_AUDIT_REQUIRED", "true")
    assert load_config().audit_required is True
    monkeypatch.setenv("MCP_AUDIT_REQUIRED", "0")
    assert load_config().audit_required is False


def test_load_config_query_limit_defaults(monkeypatch):
    from ssdf_mcp_query.config import load_config

    monkeypatch.setenv("CH_PASSWORD", "x")
    monkeypatch.setenv("MCP_AUTH_TOKEN", "t")
    monkeypatch.delenv("MCP_MAX_RESULT_ROWS", raising=False)
    monkeypatch.delenv("MCP_MAX_MEMORY_BYTES", raising=False)
    cfg = load_config()
    assert cfg.max_result_rows == 100000
    assert cfg.max_memory_usage == 1_000_000_000


def test_checkpoint_verify_key_paths_comma_separated(monkeypatch):
    monkeypatch.setenv("CH_PASSWORD", "x")
    monkeypatch.setenv("MCP_AUTH_TOKEN", "t")
    monkeypatch.delenv("CH_CHECKPOINT_VERIFY_KEY_PATH", raising=False)
    monkeypatch.setenv("CH_CHECKPOINT_VERIFY_KEY_PATHS", "/etc/ssdf/a.key, /etc/ssdf/b.key")
    cfg = load_config()
    assert cfg.ch_checkpoint_verify_key_paths == ("/etc/ssdf/a.key", "/etc/ssdf/b.key")


def test_checkpoint_verify_key_paths_falls_back_to_legacy_single_var(monkeypatch):
    """MEC-1610: an unrotated deployment's existing single-key env var keeps
    working untouched once the config surface moves to a keyring."""
    monkeypatch.setenv("CH_PASSWORD", "x")
    monkeypatch.setenv("MCP_AUTH_TOKEN", "t")
    monkeypatch.delenv("CH_CHECKPOINT_VERIFY_KEY_PATHS", raising=False)
    monkeypatch.setenv("CH_CHECKPOINT_VERIFY_KEY_PATH", "/etc/ssdf/checkpoint-verify.key")
    cfg = load_config()
    assert cfg.ch_checkpoint_verify_key_paths == ("/etc/ssdf/checkpoint-verify.key",)


def test_checkpoint_verify_key_paths_empty_when_unconfigured(monkeypatch):
    monkeypatch.setenv("CH_PASSWORD", "x")
    monkeypatch.setenv("MCP_AUTH_TOKEN", "t")
    monkeypatch.delenv("CH_CHECKPOINT_VERIFY_KEY_PATHS", raising=False)
    monkeypatch.delenv("CH_CHECKPOINT_VERIFY_KEY_PATH", raising=False)
    cfg = load_config()
    assert cfg.ch_checkpoint_verify_key_paths == ()
