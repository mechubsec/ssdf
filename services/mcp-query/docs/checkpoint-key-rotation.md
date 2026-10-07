# Checkpoint verifying key rotation (MEC-1610)

`verify_audit.py` and `scripts/checkpoint_audit.py` verify `ssdf.audit`
checkpoint signatures against a **keyring**: zero or more Ed25519 verifying
keys, configured via `CH_CHECKPOINT_VERIFY_KEY_PATHS` (comma-separated
paths; `CH_CHECKPOINT_VERIFY_KEY_PATH` with a single path still works for an
unrotated deployment). Each checkpoint row carries a `key_id` recorded at
signing time; verification loads every configured key, fingerprints it
**locally** (never trusting the `key_id` column itself — that column lives
in ClickHouse and is exactly the kind of value this feature's threat model
treats as attacker-reachable), and picks whichever ring member's fingerprint
matches the checkpoint's `key_id`.

A checkpoint whose `key_id` matches no locally loaded key reports
`unverifiable_checkpoint`, same as always — the keyring changes *which* key
verification tries, not whether it fails closed.

## Key separation from ClickHouse admin credentials

The checkpoint verifying key (public) and its matching signing key
(private, used only by `scripts/checkpoint_audit.py` via
`mecmcp-audit-checkpoint`) are not ClickHouse credentials and must not be
stored or distributed alongside `CH_AUDIT_PASSWORD` /
`CH_CHECKPOINT_PASSWORD`. Anyone who can read or write `ssdf.audit_checkpoints`
rows (i.e. has ClickHouse access) must not thereby gain the signing key —
that would let them forge a checkpoint for rows they also control, defeating
the point of checkpoint verification. Keep the signing key on the host that
runs `scripts/checkpoint_audit.py` (mode 0600, as the signing binary
enforces) and distribute only the public verifying key to hosts running
`verify_audit.py`.

## Rotating a key

1. Generate a new keypair with `mecmcp-audit-keygen` (mechubsec/mecmcp,
   `crates/mecmcp-audit`). This prints the new public verifying key and
   writes the private signing key to the path you give it, mode 0600.
2. Distribute the new public verifying key to every host that runs
   `verify_audit.py` or `scripts/checkpoint_audit.py --binary
   mecmcp-audit-checkpoint` for self-verification, **alongside** the
   existing key — add its path to `CH_CHECKPOINT_VERIFY_KEY_PATHS` rather
   than replacing the old path. This is the overlap window: both the
   retiring and incoming key must be present in every verifier's keyring
   for as long as any checkpoint signed with the retiring key is still
   within its ~90-day checkpoint lifetime, or verification of those older
   checkpoints will report `unverifiable_checkpoint` the moment the old key
   drops out of the ring.
3. Point `scripts/checkpoint_audit.py`'s `CHECKPOINT_SIGNING_KEY_PATH` (the
   *signing* key, separate from the verify keyring) at the new private key
   once you want new checkpoints signed with it. Checkpoints already signed
   with the old key keep verifying as long as step 2's overlap holds.
4. Once every checkpoint signed with the retiring key has left the ~90-day
   checkpoint retention window (check with `scripts/checkpoint_audit.py` or
   a direct query against `ssdf.audit_checkpoints` for the oldest row whose
   `key_id` is the retiring key's fingerprint), remove the retiring key's
   path from `CH_CHECKPOINT_VERIFY_KEY_PATHS` on every host and destroy the
   retired private signing key.

## Fingerprint algorithm

A key's `key_id` is `sha256(base64_standard_encode(raw_32_byte_verifying_key))[:8]`,
hex-encoded (16 hex characters) — the same computation on both sides of the
Rust/Python boundary (`mecmcp-audit::checkpoint::key_id` and
`ssdf_mcp_query.checkpoint_verify.key_fingerprint`). It identifies which key
signed a checkpoint; it carries no trust of its own and is never read from
ClickHouse to select a verification key.
