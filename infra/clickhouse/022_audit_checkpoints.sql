-- infra/clickhouse/022_audit_checkpoints.sql
--
-- Apply (same envsubst pattern as 008_public_views.sql): inject
-- CHECKPOINT_PW before applying (never commit a real value). The
-- `: "${CH_CHECKPOINT_PASSWORD:?}"` guard aborts on an unset/empty source
-- variable instead of letting envsubst substitute an empty string, which
-- would otherwise create a passworded-by-empty-string user with INSERT on
-- audit_checkpoints:
--   : "${CH_CHECKPOINT_PASSWORD:?}" && CHECKPOINT_PW="$CH_CHECKPOINT_PASSWORD" \
--     envsubst < 022_audit_checkpoints.sql \
--     | clickhouse-client --host <ct104> --multiquery
--
-- MEC-565: signed chain-head checkpoints anchoring ssdf.audit (007_audit.sql)
-- beyond its 90-day TTL (009_audit_hash_chain.sql). Once a chain's genesis row
-- (prev_hash=="") ages out, verify_audit.py has nothing to walk from -- a
-- checkpoint is a durable, signed statement of a chain's head at a point in
-- time that verify_audit.py can anchor to instead.
--
-- No TTL on this table: a checkpoint must outlive the rows it anchors, or it
-- cannot do its job. Checkpoints are small (one row per (tier, server_id) per
-- checkpoint run, roughly daily) relative to ssdf.audit's volume.
--
-- Signing happens outside ClickHouse (mecmcp-audit-checkpoint, Ed25519, v0.25.0+
-- of mecmcp) -- this table stores the already-signed result verbatim. See
-- crates/mecmcp-audit/src/checkpoint.rs (mechubsec/mecmcp) for the signed
-- payload's field set and the digest/signature format verify_audit.py checks
-- against (checkpoint_verify.py in this repo).
-- checkpoint_ts is stored as the verbatim RFC3339 string the signer produced
-- and signed over (mecmcp_audit::checkpoint::Checkpoint.checkpoint_ts),
-- deliberately NOT as a ClickHouse DateTime64: the signature covers the exact
-- bytes of the canonical JSON, including this field's literal string
-- rendering, and round-tripping through DateTime64 (parsing then
-- reformatting) is not guaranteed to reproduce the same bytes. Storing it as
-- String is what makes checkpoint_verify.py's digest recomputation match the
-- one the Rust signer produced.
CREATE TABLE IF NOT EXISTS ssdf.audit_checkpoints
(
    tier           LowCardinality(String),
    server_id      String,
    row_count      UInt64,
    head_row_hash  String,
    checkpoint_ts  String,
    signature      String,
    key_id         String,
    inserted_at    DateTime64(3, 'UTC') DEFAULT now64(3, 'UTC')
)
ENGINE = MergeTree
ORDER BY (tier, server_id, checkpoint_ts);

-- ssdf_checkpoint: the orchestrator identity (scripts/checkpoint_audit.py).
-- Needs SELECT on ssdf.audit to read the current chain tip, and INSERT+SELECT
-- on audit_checkpoints -- SELECT so it can find the previous checkpoint and
-- compute each new one's row_count as a running total rather than a count of
-- whatever currently survives the 90-day TTL (which would make row_count
-- *shrink* as old rows expire, defeating the point of anchoring past them).
-- No ALTER/DELETE: checkpoints, like the audit trail itself, are append-only.
CREATE USER IF NOT EXISTS ssdf_checkpoint IDENTIFIED WITH sha256_password BY '${CHECKPOINT_PW}';
GRANT SELECT ON ssdf.audit TO ssdf_checkpoint;
GRANT INSERT, SELECT ON ssdf.audit_checkpoints TO ssdf_checkpoint;

-- ssdf_audit_verify (009_audit_hash_chain.sql) is verify_audit.py's read
-- identity; it needs to read checkpoints to anchor past an expired genesis.
GRANT SELECT ON ssdf.audit_checkpoints TO ssdf_audit_verify;
