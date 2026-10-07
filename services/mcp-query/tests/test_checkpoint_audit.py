from __future__ import annotations

import base64
import datetime as dt
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import checkpoint_audit  # noqa: E402
from ssdf_mcp_query.audit_chain import compute_row_hash  # noqa: E402
from ssdf_mcp_query.checkpoint_verify import canonical_digest, key_fingerprint  # noqa: E402

from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
)


def _keyring(verifying_key: bytes) -> dict[str, bytes]:
    return {key_fingerprint(verifying_key): verifying_key}


class _FakeResult:
    def __init__(self, result_rows):
        self.result_rows = result_rows


class _FakeClient:
    def __init__(self, audit_rows=(), checkpoint_rows=(), evidence_rows=()):
        self._audit_rows = list(audit_rows)
        self._checkpoint_rows = list(checkpoint_rows)
        self._evidence_rows = list(evidence_rows)
        self.inserted: list[tuple[str, list, list]] = []

    def query(self, sql, parameters=None):
        if "audit_evidence" in sql:
            return _FakeResult(list(self._evidence_rows))
        if "FROM ssdf.audit " in sql or sql.rstrip().endswith("ssdf.audit"):
            return _FakeResult(list(self._audit_rows))
        if "audit_checkpoints" in sql:
            return _FakeResult(list(self._checkpoint_rows))
        raise AssertionError(f"unexpected query: {sql}")

    def insert(self, table, data, column_names):
        self.inserted.append((table, data, column_names))


def _audit_row(i: int, tier: str, prev_hash: str, args: str = "{}") -> tuple:
    row = {
        "ts": dt.datetime(2026, 6, 10, tzinfo=dt.timezone.utc),
        "principal": "agent",
        "tier": tier,
        "tool": f"t{i}",
        "args": args,
        "data_classes": [],
        "decision": "allow",
        "row_count": i,
        "error": "",
        "client_name": "",
        "model_id": "",
        "actor_type": "",
        "prev_hash": prev_hash,
    }
    row["row_hash"] = compute_row_hash(prev_hash, row)
    return tuple(row[c] for c in checkpoint_audit._ROW_COLUMNS), row["row_hash"]


def test_fetch_rows_by_chain_groups_by_tier_and_server_id():
    sovereign_row, _ = _audit_row(0, "sovereign", "")
    evidence_args = json.dumps({"server_id": "junos-1"})
    ev_row, _ = _audit_row(1, "evidence", "", args=evidence_args)
    client = _FakeClient(audit_rows=[sovereign_row, ev_row])

    by_chain = checkpoint_audit.fetch_rows_by_chain(client)

    assert ("sovereign", "") in by_chain
    assert ("evidence", "junos-1") in by_chain
    assert len(by_chain[("sovereign", "")]) == 1
    assert len(by_chain[("evidence", "junos-1")]) == 1


def test_fetch_previous_checkpoints_keeps_latest_per_chain():
    rows = [
        ("sovereign", "", 4, "h1", "2026-09-01T00:00:00.000Z", "sig1", "k1"),
        ("sovereign", "", 7, "h2", "2026-09-02T00:00:00.000Z", "sig2", "k2"),
    ]
    client = _FakeClient(checkpoint_rows=rows)

    latest = checkpoint_audit.fetch_previous_checkpoints(client)

    assert latest[("sovereign", "")]["row_count"] == 7
    assert latest[("sovereign", "")]["head_row_hash"] == "h2"


def test_fetch_checkpoints_by_chain_returns_every_checkpoint():
    """Unlike fetch_previous_checkpoints, self-verification needs every
    checkpoint for a chain, not just the latest -- verify_tier matches by
    head_row_hash, which may belong to an older one."""
    rows = [
        ("sovereign", "", 4, "h1", "2026-09-01T00:00:00.000Z", "sig1", "k1"),
        ("sovereign", "", 7, "h2", "2026-09-02T00:00:00.000Z", "sig2", "k2"),
    ]
    client = _FakeClient(checkpoint_rows=rows)

    by_chain = checkpoint_audit.fetch_checkpoints_by_chain(client)

    checkpoints = by_chain[("sovereign", "")]
    assert {c.head_row_hash for c in checkpoints} == {"h1", "h2"}


def test_fetch_evidence_rows_by_chain_groups_and_bounds_by_age():
    sovereign_row, _ = _audit_row(0, "sovereign", "")
    client = _FakeClient(evidence_rows=[sovereign_row])
    now = dt.datetime(2026, 9, 28, tzinfo=dt.timezone.utc)

    by_chain = checkpoint_audit.fetch_evidence_rows_by_chain(client, now)

    assert ("sovereign", "") in by_chain
    assert len(by_chain[("sovereign", "")]) == 1


def test_format_checkpoint_ts_is_millisecond_precision_utc():
    now = dt.datetime(2026, 9, 28, 0, 0, 0, 123456, tzinfo=dt.timezone.utc)
    assert checkpoint_audit.format_checkpoint_ts(now) == "2026-09-28T00:00:00.123Z"


def test_format_checkpoint_ts_converts_naive_to_utc():
    now = dt.datetime(2026, 9, 28, 0, 0, 0)
    assert checkpoint_audit.format_checkpoint_ts(now) == "2026-09-28T00:00:00.000Z"


def test_sign_checkpoint_raises_on_nonzero_exit(monkeypatch):
    class _Proc:
        returncode = 1
        stdout = ""
        stderr = "bad key"

    monkeypatch.setattr(checkpoint_audit.subprocess, "run", lambda *a, **k: _Proc())
    with pytest.raises(RuntimeError, match="bad key"):
        checkpoint_audit.sign_checkpoint("binary", "key", {"tier": "sovereign"})


def test_sign_checkpoint_raises_on_invalid_json(monkeypatch):
    class _Proc:
        returncode = 0
        stdout = "not json"
        stderr = ""

    monkeypatch.setattr(checkpoint_audit.subprocess, "run", lambda *a, **k: _Proc())
    with pytest.raises(RuntimeError, match="invalid JSON"):
        checkpoint_audit.sign_checkpoint("binary", "key", {"tier": "sovereign"})


def test_sign_checkpoint_raises_on_missing_fields(monkeypatch):
    class _Proc:
        returncode = 0
        stdout = json.dumps({"tier": "sovereign"})
        stderr = ""

    monkeypatch.setattr(checkpoint_audit.subprocess, "run", lambda *a, **k: _Proc())
    with pytest.raises(RuntimeError, match="missing field"):
        checkpoint_audit.sign_checkpoint("binary", "key", {"tier": "sovereign"})


def test_sign_checkpoint_returns_parsed_output(monkeypatch):
    signed = {c: "x" for c in checkpoint_audit._CHECKPOINT_COLUMNS}
    signed["tier"] = "sovereign"  # must echo the payload field sign_checkpoint checks

    class _Proc:
        returncode = 0
        stdout = json.dumps(signed)
        stderr = ""

    captured = {}

    def fake_run(cmd, input, capture_output, text, timeout):
        captured["cmd"] = cmd
        captured["input"] = input
        return _Proc()

    monkeypatch.setattr(checkpoint_audit.subprocess, "run", fake_run)
    out = checkpoint_audit.sign_checkpoint("the-binary", "the-key", {"tier": "sovereign"})

    assert out == signed
    assert captured["cmd"] == ["the-binary", "the-key"]
    assert json.loads(captured["input"]) == {"tier": "sovereign"}


def test_sign_checkpoint_raises_when_signer_alters_a_payload_field(monkeypatch):
    """The signer must echo back the exact fields it was asked to sign. A
    signer that silently substitutes a different row_count must not be
    trusted."""
    payload = {
        "tier": "sovereign",
        "server_id": "",
        "row_count": 4,
        "head_row_hash": "abc",
        "checkpoint_ts": "2026-09-28T00:00:00.000Z",
    }
    signed = {**payload, "row_count": 999, "signature": "sig", "key_id": "k1"}

    class _Proc:
        returncode = 0
        stdout = json.dumps(signed)
        stderr = ""

    monkeypatch.setattr(checkpoint_audit.subprocess, "run", lambda *a, **k: _Proc())
    with pytest.raises(RuntimeError, match="row_count"):
        checkpoint_audit.sign_checkpoint("binary", "key", payload)


def test_sign_checkpoint_raises_when_signature_does_not_verify(monkeypatch):
    """When a verifying key is supplied, an invalid signature must be caught
    before the checkpoint ever reaches the insert path."""
    payload = {
        "tier": "sovereign",
        "server_id": "",
        "row_count": 4,
        "head_row_hash": "abc",
        "checkpoint_ts": "2026-09-28T00:00:00.000Z",
    }
    signed = {**payload, "signature": base64.b64encode(b"\x00" * 64).decode(), "key_id": "k1"}

    class _Proc:
        returncode = 0
        stdout = json.dumps(signed)
        stderr = ""

    monkeypatch.setattr(checkpoint_audit.subprocess, "run", lambda *a, **k: _Proc())
    private_key = Ed25519PrivateKey.generate()
    verifying_key = private_key.public_key().public_bytes_raw()
    with pytest.raises(RuntimeError, match="invalid signature"):
        checkpoint_audit.sign_checkpoint("binary", "key", payload, keyring=_keyring(verifying_key))


def test_sign_checkpoint_accepts_a_genuinely_valid_signature(monkeypatch):
    payload = {
        "tier": "sovereign",
        "server_id": "",
        "row_count": 4,
        "head_row_hash": "abc",
        "checkpoint_ts": "2026-09-28T00:00:00.000Z",
    }
    private_key = Ed25519PrivateKey.generate()
    verifying_key = private_key.public_key().public_bytes_raw()

    from ssdf_mcp_query.checkpoint_verify import Checkpoint

    key_id = key_fingerprint(verifying_key)
    unsigned = Checkpoint(signature="", key_id=key_id, **payload)
    signature = base64.b64encode(private_key.sign(canonical_digest(unsigned))).decode()
    signed = {**payload, "signature": signature, "key_id": key_id}

    class _Proc:
        returncode = 0
        stdout = json.dumps(signed)
        stderr = ""

    monkeypatch.setattr(checkpoint_audit.subprocess, "run", lambda *a, **k: _Proc())
    out = checkpoint_audit.sign_checkpoint(
        "binary", "key", payload, keyring=_keyring(verifying_key)
    )
    assert out == signed


def test_run_checkpoints_a_fresh_chain_and_inserts_it(monkeypatch):
    (row_tuple, row_hash) = _audit_row(0, "sovereign", "")
    client = _FakeClient(audit_rows=[row_tuple], checkpoint_rows=[])

    signed = {
        "tier": "sovereign",
        "server_id": "",
        "row_count": 1,
        "head_row_hash": row_hash,
        "checkpoint_ts": "2026-06-10T00:00:00.000Z",
        "signature": "sig",
        "key_id": "k1",
    }
    monkeypatch.setattr(checkpoint_audit, "sign_checkpoint", lambda *a, **k: signed)

    result = checkpoint_audit.run(client, "binary", "key")

    assert result.inserted == [signed]
    assert result.skipped == []
    assert len(client.inserted) == 1
    table, data, columns = client.inserted[0]
    assert table == "ssdf.audit_checkpoints"
    assert columns == checkpoint_audit._CHECKPOINT_COLUMNS
    assert data == [[signed[c] for c in checkpoint_audit._CHECKPOINT_COLUMNS]]


def test_run_skips_chains_with_nothing_new(monkeypatch):
    (row_tuple, row_hash) = _audit_row(0, "sovereign", "")
    checkpoint_row = (
        "sovereign",
        "",
        1,
        row_hash,
        "2026-06-10T00:00:00.000Z",
        "sig",
        "k1",
    )
    client = _FakeClient(audit_rows=[row_tuple], checkpoint_rows=[checkpoint_row])

    def fail_sign(*args, **kwargs):
        raise AssertionError("should not sign an unchanged chain")

    monkeypatch.setattr(checkpoint_audit, "sign_checkpoint", fail_sign)

    result = checkpoint_audit.run(client, "binary", "key")

    assert result.inserted == []
    assert result.skipped == []
    assert client.inserted == []


def test_run_skips_a_multi_row_idle_chain_without_flagging_it_as_stray(monkeypatch):
    """A chain with more than one row, checkpointed at its current tip, is
    the normal idle case (no new rows since the last run) -- not tampering.
    rows_unreachable_from_previous must not flag the previous head's own
    still-live ancestors as stray just because they are not reachable
    *forward* from that head."""
    genesis_tuple, genesis_hash = _audit_row(0, "sovereign", "")
    tip_tuple, tip_hash = _audit_row(1, "sovereign", genesis_hash)
    checkpoint_row = (
        "sovereign",
        "",
        2,
        tip_hash,
        "2026-06-10T00:00:00.000Z",
        "sig",
        "k1",
    )
    client = _FakeClient(audit_rows=[genesis_tuple, tip_tuple], checkpoint_rows=[checkpoint_row])

    def fail_sign(*args, **kwargs):
        raise AssertionError("should not sign an unchanged chain")

    monkeypatch.setattr(checkpoint_audit, "sign_checkpoint", fail_sign)

    result = checkpoint_audit.run(client, "binary", "key")

    assert result.inserted == []
    assert result.skipped == []
    assert client.inserted == []


def test_run_refuses_to_checkpoint_a_chain_with_a_content_edit(monkeypatch):
    """compute_next_checkpoint only walks prev_hash -> row_hash linkage and
    never recomputes a row's content hash, so a row edited after being
    written (stored row_hash no longer matches its content, but linkage to
    the next row is untouched) would otherwise become part of a signed,
    trusted head. The self-verification step in run() must catch this via
    verify_tier's content-integrity check and refuse to checkpoint the chain
    at all."""
    genesis_tuple, genesis_hash = _audit_row(0, "sovereign", "")
    tampered_row = dict(
        zip(checkpoint_audit._ROW_COLUMNS, _audit_row(1, "sovereign", genesis_hash)[0])
    )
    tampered_row["tool"] = "TAMPERED"  # content changed after row_hash was stored
    tampered_tuple = tuple(tampered_row[c] for c in checkpoint_audit._ROW_COLUMNS)
    client = _FakeClient(audit_rows=[genesis_tuple, tampered_tuple])

    def fail_sign(*args, **kwargs):
        raise AssertionError("should not sign a chain with a content edit")

    monkeypatch.setattr(checkpoint_audit, "sign_checkpoint", fail_sign)

    result = checkpoint_audit.run(client, "binary", "key")

    assert result.inserted == []
    assert result.skipped == [("sovereign", "")]


def test_run_refuses_to_checkpoint_a_forked_chain(monkeypatch):
    """A chain with two rows naming the same prev_hash is a fork.
    verify_tier's self-verification in run() must catch it and skip the
    chain before compute_next_checkpoint ever runs."""
    genesis_tuple, genesis_hash = _audit_row(0, "sovereign", "")
    real_child_tuple, _ = _audit_row(1, "sovereign", genesis_hash)
    sibling_row = dict(
        zip(checkpoint_audit._ROW_COLUMNS, _audit_row(2, "sovereign", genesis_hash)[0])
    )
    sibling_tuple = tuple(sibling_row[c] for c in checkpoint_audit._ROW_COLUMNS)
    client = _FakeClient(audit_rows=[genesis_tuple, real_child_tuple, sibling_tuple])

    def fail_sign(*args, **kwargs):
        raise AssertionError("should not sign a forked chain")

    monkeypatch.setattr(checkpoint_audit, "sign_checkpoint", fail_sign)

    result = checkpoint_audit.run(client, "binary", "key")

    assert result.inserted == []
    assert result.skipped == [("sovereign", "")]


def test_run_self_verifies_past_an_expired_genesis_via_the_evidence_bridge(monkeypatch):
    """Once a chain's genesis has aged out of ssdf.audit, a daily checkpoint
    schedule almost never sits at exactly the row the TTL
    most recently evicted -- it sits wherever the chain tip was when the job
    last ran. Self-verification must be able to bridge that gap through
    ssdf.audit_evidence the same way verify_audit.py does, or the
    checkpointer stalls the first time any chain's genesis expires."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from ssdf_mcp_query.checkpoint_verify import Checkpoint, canonical_digest

    _, genesis_hash = _audit_row(0, "sovereign", "")
    bridge_values, bridge_hash = _audit_row(1, "sovereign", genesis_hash)
    bridge_row = dict(zip(checkpoint_audit._ROW_COLUMNS, bridge_values))
    s1_tuple, s1_hash = _audit_row(2, "sovereign", bridge_hash)
    s2_tuple, s2_hash = _audit_row(3, "sovereign", s1_hash)

    signing_key = Ed25519PrivateKey.generate()
    verifying_key = signing_key.public_key().public_bytes_raw()

    def _sign(head_row_hash: str, row_count: int, checkpoint_ts: str, key_id: str) -> tuple:
        unsigned = Checkpoint(
            tier="sovereign",
            server_id="",
            row_count=row_count,
            head_row_hash=head_row_hash,
            checkpoint_ts=checkpoint_ts,
            signature="",
            key_id=key_id,
        )
        signature = base64.b64encode(signing_key.sign(canonical_digest(unsigned))).decode()
        return ("sovereign", "", row_count, head_row_hash, checkpoint_ts, signature, key_id)

    key_id = key_fingerprint(verifying_key)
    # Anchors the now-expired genesis; old enough to stand in for it.
    anchor_checkpoint = _sign(genesis_hash, 1, "2026-01-01T00:00:00.000Z", key_id)
    # The most recent checkpoint, used by compute_next_checkpoint's forward
    # walk -- unrelated to the self-verification bridge above. Dated within
    # a day of `now` (rather than further back) so MEC-1634's
    # stale_checkpoint check does not fire on this fixture's rows, which are
    # all hardcoded to ts=2026-06-10 regardless of `now` (see _audit_row).
    recent_checkpoint = _sign(s1_hash, 3, "2026-05-31T00:00:00.000Z", key_id)

    client = _FakeClient(
        audit_rows=[s1_tuple, s2_tuple],
        checkpoint_rows=[anchor_checkpoint, recent_checkpoint],
        evidence_rows=[tuple(bridge_row[c] for c in checkpoint_audit._ROW_COLUMNS)],
    )

    signed = {
        "tier": "sovereign",
        "server_id": "",
        "row_count": 4,
        "head_row_hash": s2_hash,
        "checkpoint_ts": "2026-06-01T00:00:00.000Z",
        "signature": "sig",
        "key_id": "k3",
    }
    monkeypatch.setattr(checkpoint_audit, "sign_checkpoint", lambda *a, **k: signed)

    now = dt.datetime(2026, 6, 1, tzinfo=dt.timezone.utc)  # ~151 days after the anchor
    result = checkpoint_audit.run(client, "binary", "key", now=now, keyring=_keyring(verifying_key))

    assert result.skipped == [], "self-verification must bridge through audit_evidence, not stall"
    assert result.inserted == [signed]


def test_run_checkpoints_a_stale_chain_instead_of_skipping_it_forever(monkeypatch):
    """The checkpoint job is the only thing that can extend a chain's newest
    verified checkpoint, so its own self-verification must not refuse to do
    so just because that checkpoint has fallen behind schedule -- that would
    be self-perpetuating and leave the chain stuck skipped indefinitely."""
    from ssdf_mcp_query.checkpoint_verify import Checkpoint, canonical_digest

    genesis_tuple, genesis_hash = _audit_row(0, "sovereign", "")
    second_tuple, second_hash = _audit_row(1, "sovereign", genesis_hash)

    signing_key = Ed25519PrivateKey.generate()
    verifying_key = signing_key.public_key().public_bytes_raw()

    def _sign(head_row_hash: str, row_count: int, checkpoint_ts: str, key_id: str) -> tuple:
        unsigned = Checkpoint(
            tier="sovereign",
            server_id="",
            row_count=row_count,
            head_row_hash=head_row_hash,
            checkpoint_ts=checkpoint_ts,
            signature="",
            key_id=key_id,
        )
        signature = base64.b64encode(signing_key.sign(canonical_digest(unsigned))).decode()
        return ("sovereign", "", row_count, head_row_hash, checkpoint_ts, signature, key_id)

    checkpoint_row = _sign(
        genesis_hash, 1, "2026-06-09T23:59:59.000Z", key_fingerprint(verifying_key)
    )
    client = _FakeClient(audit_rows=[genesis_tuple, second_tuple], checkpoint_rows=[checkpoint_row])

    signed = {
        "tier": "sovereign",
        "server_id": "",
        "row_count": 2,
        "head_row_hash": second_hash,
        "checkpoint_ts": "2026-06-13T00:00:00.000Z",
        "signature": "sig",
        "key_id": "k2",
    }
    monkeypatch.setattr(checkpoint_audit, "sign_checkpoint", lambda *a, **k: signed)

    now = dt.datetime(2026, 6, 13, tzinfo=dt.timezone.utc)  # checkpoint is well past due
    result = checkpoint_audit.run(client, "binary", "key", now=now, keyring=_keyring(verifying_key))

    assert result.skipped == [], "a stale checkpoint must still be extendable, not stuck forever"
    assert result.inserted == [signed]


def test_run_flags_previous_checkpoint_head_unreachable_as_skipped_not_silent(monkeypatch):
    """If the previous checkpoint's head row is gone from the chain's current
    rows and nothing chains from it either, compute_next_checkpoint
    legitimately returns None -- but
    run() must not let that fall through in silence. Without this backstop,
    a deleted checkpointed head (e.g. by someone with ClickHouse admin
    access, after the checkpoint was taken) stops the chain from ever being
    checkpointed again with no visible signal, until genesis itself ages
    out ~90 days later. No verifying key is configured here, so self-
    verification's checkpoint_head_missing check (verify_audit.py) stays
    silent -- this test is specifically for the backstop in run() that
    still catches it."""
    row0_tuple, row0_hash = _audit_row(0, "sovereign", "")
    row1_tuple, row1_hash = _audit_row(1, "sovereign", row0_hash)
    row2_tuple, row2_hash = _audit_row(2, "sovereign", row1_hash)
    _, row3_hash = _audit_row(3, "sovereign", row2_hash)
    _, row4_hash = _audit_row(4, "sovereign", row3_hash)

    checkpoint_row = (
        "sovereign",
        "",
        5,
        row4_hash,  # the checkpointed head; rows 3-4 have since been deleted
        "2026-06-05T00:00:00.000Z",
        "sig",
        "k1",
    )
    client = _FakeClient(
        audit_rows=[row0_tuple, row1_tuple, row2_tuple],
        checkpoint_rows=[checkpoint_row],
    )

    def fail_sign(*args, **kwargs):
        raise AssertionError("should not sign without a verified anchor")

    monkeypatch.setattr(checkpoint_audit, "sign_checkpoint", fail_sign)

    result = checkpoint_audit.run(client, "binary", "key")

    assert result.inserted == []
    assert result.skipped == [("sovereign", "")]


def test_run_flags_a_fully_deleted_chain_as_skipped_not_silent(monkeypatch):
    """A chain with ZERO rows left in ssdf.audit (every row removed) must
    still be walked and flagged, not silently absent from both `inserted`
    and `skipped` just because it has no entry in `rows_by_chain`."""
    _, row0_hash = _audit_row(0, "sovereign", "")
    checkpoint_row = (
        "sovereign",
        "",
        1,
        row0_hash,
        "2026-06-05T00:00:00.000Z",
        "sig",
        "k1",
    )
    client = _FakeClient(audit_rows=[], checkpoint_rows=[checkpoint_row])

    def fail_sign(*args, **kwargs):
        raise AssertionError("should not sign a chain with no rows")

    monkeypatch.setattr(checkpoint_audit, "sign_checkpoint", fail_sign)

    result = checkpoint_audit.run(client, "binary", "key")

    assert result.inserted == []
    assert result.skipped == [("sovereign", "")]


def test_run_refuses_to_extend_an_unsigned_previous_checkpoint(monkeypatch):
    """A previous checkpoint that fails signature verification is not
    extended."""
    genesis_tuple, genesis_hash = _audit_row(0, "sovereign", "")
    tip_tuple, tip_hash = _audit_row(1, "sovereign", genesis_hash)

    private_key = Ed25519PrivateKey.generate()
    verifying_key = private_key.public_key().public_bytes_raw()

    forged_checkpoint_row = (
        "sovereign",
        "",
        1_000_000,  # unsigned row_count
        genesis_hash,
        "2020-01-01T00:00:00.000Z",
        base64.b64encode(b"\x00" * 64).decode(),  # not a valid signature
        "deadbeef",
    )
    client = _FakeClient(
        audit_rows=[genesis_tuple, tip_tuple], checkpoint_rows=[forged_checkpoint_row]
    )

    def fail_sign(*args, **kwargs):
        raise AssertionError("should not sign on top of an unverified previous checkpoint")

    monkeypatch.setattr(checkpoint_audit, "sign_checkpoint", fail_sign)

    result = checkpoint_audit.run(client, "binary", "key", keyring=_keyring(verifying_key))

    assert result.inserted == []
    assert result.skipped == [("sovereign", "")]
    assert client.inserted == []


def test_main_requires_verify_key_path(monkeypatch):
    """Without a verifying keyring, self-verification of a chain whose
    genesis has expired silently skips the
    anchor check instead of failing closed. main() must require the key
    path(s) up front, the same as the signing key and password."""
    monkeypatch.setattr(sys, "argv", ["checkpoint_audit.py"])
    monkeypatch.setenv("CHECKPOINT_SIGNING_KEY_PATH", "/tmp/signing.key")
    monkeypatch.setenv("CH_CHECKPOINT_PASSWORD", "pw")
    monkeypatch.delenv("CH_CHECKPOINT_VERIFY_KEY_PATHS", raising=False)
    monkeypatch.delenv("CH_CHECKPOINT_VERIFY_KEY_PATH", raising=False)

    assert checkpoint_audit.main() == 2


def test_main_requires_verify_key_to_be_loadable(monkeypatch, tmp_path):
    bad_key = tmp_path / "verify.key"
    bad_key.write_text("not valid base64!!")
    monkeypatch.setattr(sys, "argv", ["checkpoint_audit.py"])
    monkeypatch.setenv("CHECKPOINT_SIGNING_KEY_PATH", "/tmp/signing.key")
    monkeypatch.setenv("CH_CHECKPOINT_PASSWORD", "pw")
    monkeypatch.delenv("CH_CHECKPOINT_VERIFY_KEY_PATHS", raising=False)
    monkeypatch.setenv("CH_CHECKPOINT_VERIFY_KEY_PATH", str(bad_key))

    assert checkpoint_audit.main() == 2


def test_main_accepts_a_keyring_of_multiple_paths(monkeypatch, tmp_path):
    """MEC-1610: CH_CHECKPOINT_VERIFY_KEY_PATHS accepts a comma-separated
    list, loading every path into the keyring rather than only the first."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key_a = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    key_b = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    path_a = tmp_path / "a.key"
    path_b = tmp_path / "b.key"
    path_a.write_text(base64.b64encode(key_a).decode())
    path_b.write_text(base64.b64encode(key_b).decode())

    monkeypatch.setenv("CH_CHECKPOINT_VERIFY_KEY_PATHS", f"{path_a},{path_b}")
    monkeypatch.delenv("CH_CHECKPOINT_VERIFY_KEY_PATH", raising=False)

    keyring = checkpoint_audit.load_checkpoint_verifying_keyring()
    assert keyring == {**_keyring(key_a), **_keyring(key_b)}
