"""Tokens must not be recoverable from anything the server keeps (issue #7)."""

from __future__ import annotations

import asyncio
import json

import pytest

from ssdf_mcp_query.config import ConfigError, load_token_map
from ssdf_mcp_query.mint_token import build_entry
from ssdf_mcp_query.tokenstore import (
    DIGEST_PREFIX,
    DigestTokenVerifier,
    InsecureTokenFileError,
    assert_file_mode_private,
    digest_for,
    is_digest,
    mint_token,
    normalize_token_keys,
    verify_against,
)


def _write(tmp_path, payload, mode=0o600):
    f = tmp_path / "tokens.json"
    f.write_text(json.dumps(payload))
    f.chmod(mode)
    return f


# --- the secret must not survive anywhere ----------------------------------


def test_digest_does_not_contain_the_token():
    token = mint_token()
    stored = digest_for(token)
    assert stored.startswith(DIGEST_PREFIX)
    assert token not in stored


def test_digest_is_stable_and_distinct():
    assert digest_for("a") == digest_for("a")
    assert digest_for("a") != digest_for("b")


def test_minted_tokens_are_unique():
    assert len({mint_token() for _ in range(100)}) == 100


def test_loaded_map_is_keyed_by_digest_not_by_token(tmp_path, monkeypatch):
    f = _write(tmp_path, {digest_for("sekrit"): {"principal": "p"}})
    monkeypatch.setenv("MCP_TOKENS_FILE", str(f))
    tokens = load_token_map()
    assert set(tokens) == {digest_for("sekrit")}
    assert "sekrit" not in tokens


# --- the file must not be readable by anyone else ---------------------------


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o666, 0o660])
def test_group_or_world_readable_token_file_is_refused(tmp_path, mode):
    f = _write(tmp_path, {digest_for("t"): {"principal": "p"}}, mode=mode)
    with pytest.raises(InsecureTokenFileError):
        assert_file_mode_private(f)


@pytest.mark.parametrize("mode", [0o600, 0o400])
def test_owner_only_token_file_is_accepted(tmp_path, mode):
    f = _write(tmp_path, {digest_for("t"): {"principal": "p"}}, mode=mode)
    assert_file_mode_private(f)  # must not raise


def test_loader_refuses_a_readable_token_file(tmp_path, monkeypatch):
    """Fail closed at startup: by the time it serves, exposure has happened."""
    f = _write(tmp_path, {digest_for("t"): {"principal": "p"}}, mode=0o644)
    monkeypatch.setenv("MCP_TOKENS_FILE", str(f))
    with pytest.raises(ConfigError, match="accessible beyond its owner"):
        load_token_map()


# --- legacy plaintext files keep working, but say so ------------------------


def test_legacy_plaintext_key_is_hashed_and_reported():
    by_digest, legacy = normalize_token_keys({"raw-token": {"principal": "old"}}, "tokens.json")
    assert set(by_digest) == {digest_for("raw-token")}
    assert legacy == ["old"]


def test_digest_keys_are_not_reported_as_legacy():
    _, legacy = normalize_token_keys({digest_for("x"): {"principal": "new"}}, "tokens.json")
    assert legacy == []


def test_a_legacy_and_digest_entry_for_one_token_is_refused():
    """Both keys resolve to the same digest; one would shadow the other's grants."""
    with pytest.raises(ValueError, match="same token digest"):
        normalize_token_keys(
            {"dup": {"principal": "a"}, digest_for("dup"): {"principal": "b"}}, "tokens.json"
        )


def test_legacy_warning_names_the_principal(tmp_path, monkeypatch, capsys):
    f = _write(tmp_path, {"still-plaintext": {"principal": "legacy-agent"}})
    monkeypatch.setenv("MCP_TOKENS_FILE", str(f))
    load_token_map()
    err = capsys.readouterr().err
    assert "legacy-agent" in err and "plaintext" in err


# --- verification ----------------------------------------------------------


def test_verify_against_matches_only_the_right_token():
    digests = {digest_for("right"): {"principal": "p"}}
    assert verify_against(digests, "right") == {"principal": "p"}
    assert verify_against(digests, "wrong") is None
    assert verify_against(digests, "") is None


def test_verifier_accepts_the_token_and_rejects_others():
    token = mint_token()
    verifier = DigestTokenVerifier({digest_for(token): {"principal": "p", "sub": "p"}})
    assert asyncio.run(verifier.verify_token(token)) is not None
    assert asyncio.run(verifier.verify_token(token + "x")) is None
    assert asyncio.run(verifier.verify_token(mint_token())) is None


def test_verifier_passes_claims_through_unchanged():
    token = mint_token()
    claims = {"principal": "triage", "allowed_tools": ["query_flows"], "not_after": "2026-09-09"}
    verifier = DigestTokenVerifier({digest_for(token): claims})
    access = asyncio.run(verifier.verify_token(token))
    assert access.claims == claims


def test_verifier_holds_no_plaintext_token():
    """The whole point: nothing in the verifier's state is a usable credential."""
    token = mint_token()
    verifier = DigestTokenVerifier({digest_for(token): {"principal": "p"}})
    assert token not in json.dumps(verifier._by_digest)


# --- minting ---------------------------------------------------------------


def test_mint_entry_is_keyed_by_digest_and_carries_expiry():
    token, entry = build_entry("ops", ["query_flows"], days=90)
    (key,) = entry
    assert is_digest(key) and key == digest_for(token)
    assert entry[key]["principal"] == "ops"
    assert entry[key]["allowed_tools"] == ["query_flows"]
    assert entry[key]["not_after"].endswith("+00:00")


def test_mint_entry_without_expiry_or_tool_list():
    _, entry = build_entry("admin", None, days=None)
    (key,) = entry
    assert entry[key].keys() == {"principal", "created_at"}


def test_minted_entry_loads_and_authenticates_end_to_end(tmp_path, monkeypatch):
    """Mint -> write -> load -> verify, the path an operator actually walks."""
    token, entry = build_entry("ops", None, days=1)
    f = _write(tmp_path, entry)
    monkeypatch.setenv("MCP_TOKENS_FILE", str(f))
    tokens = load_token_map()
    assert tokens[digest_for(token)].principal == "ops"

    verifier = DigestTokenVerifier({digest_for(token): {"principal": "ops"}})
    assert asyncio.run(verifier.verify_token(token)) is not None
