"""Verify Ed25519-signed ssdf.audit chain checkpoints (MEC-565).

Checkpoints are signed outside ClickHouse by the Rust `mecmcp-audit-checkpoint`
binary (mechubsec/mecmcp, `crates/mecmcp-audit/src/checkpoint.rs`, v0.25.0+)
and stored verbatim in `ssdf.audit_checkpoints` (022_audit_checkpoints.sql).
This module is the Python side of that signature: it must reproduce the exact
same digest the Rust signer computed, or every checkpoint fails verification.

Digest = sha256(canonical_json(checkpoint)), canonical_json = JSON with keys
sorted lexically and no incidental whitespace (mecmcp-audit's
`canonical::canonical_json`). The signature covers the raw 32 digest bytes,
not the "sha256:<hex>" string (mecmcp-audit's `signing::sign_digest`).

The cross-implementation byte-for-byte agreement is pinned by a known-answer
test (tests/test_checkpoint_verify.py) generated from the actual Rust binary,
not reimplemented independently on both sides -- the dedup_token precedent
(audit_chain.py's docstring) is exactly the failure mode a hand-derived
"should be equivalent" encoding invites.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_CHECKPOINT_FIELDS = ("checkpoint_ts", "head_row_hash", "row_count", "server_id", "tier")


class CheckpointVerificationError(Exception):
    """A checkpoint's signature did not verify, or it was malformed."""


@dataclass(frozen=True)
class Checkpoint:
    """A signed anchor for one (tier, server_id) chain, as stored in
    ssdf.audit_checkpoints. Mirrors mecmcp_audit::checkpoint::Checkpoint plus
    the signature and key_id columns added when it was signed."""

    tier: str
    server_id: str
    row_count: int
    head_row_hash: str
    checkpoint_ts: str
    signature: str
    key_id: str


def canonical_digest(checkpoint: Checkpoint) -> bytes:
    """The raw 32-byte SHA-256 digest that was signed.

    Field order is fixed (sorted keys) to match mecmcp-audit's canonicaliser
    exactly -- this is NOT merely "a deterministic encoding", it is required
    to be the *same* deterministic encoding the Rust signer used.
    """
    payload = {
        "checkpoint_ts": checkpoint.checkpoint_ts,
        "head_row_hash": checkpoint.head_row_hash,
        "row_count": checkpoint.row_count,
        "server_id": checkpoint.server_id,
        "tier": checkpoint.tier,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).digest()


def verify_checkpoint_signature(checkpoint: Checkpoint, verifying_key: bytes) -> None:
    """Verify `checkpoint.signature` against `verifying_key` (raw 32-byte Ed25519 public key).

    Raises CheckpointVerificationError on any failure (bad signature, wrong
    key, malformed base64/key bytes). Never returns a bool -- a checkpoint
    that silently "verifies false" invites a caller to fall through to an
    unsigned-equivalent path instead of refusing (fail closed).
    """
    try:
        sig_bytes = base64.b64decode(checkpoint.signature, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise CheckpointVerificationError(f"invalid signature encoding: {exc}") from exc

    try:
        public_key = Ed25519PublicKey.from_public_bytes(verifying_key)
    except ValueError as exc:
        raise CheckpointVerificationError(f"invalid verifying key: {exc}") from exc

    digest = canonical_digest(checkpoint)
    try:
        public_key.verify(sig_bytes, digest)
    except InvalidSignature as exc:
        raise CheckpointVerificationError("checkpoint signature does not verify") from exc


def load_verifying_key(path: str) -> bytes:
    """Load a base64-encoded Ed25519 verifying key from a file.

    Same encoding as mecmcp-audit's `encode_verifying_key` (standard base64,
    padded) -- the key distributed alongside the checkpoint job's deploy
    config, per checkpoint.rs's key-management note.
    """
    text = open(path, encoding="utf-8").read().strip()
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise CheckpointVerificationError(f"invalid verifying key file {path}: {exc}") from exc
