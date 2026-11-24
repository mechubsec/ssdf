-- infra/clickhouse/029_policy_drift.sql
--
-- Apply (same envsubst pattern as 023_audit_evidence.sql): inject DRIFT_PW
-- before applying (never commit a real value). The `:?` guard aborts on an
-- unset/empty source variable instead of letting envsubst substitute an empty
-- string, which would create a user with an empty password:
--   : "${CH_DRIFT_PASSWORD:?}" && DRIFT_PW="$CH_DRIFT_PASSWORD" \
--     envsubst < 029_policy_drift.sql \
--     | clickhouse-client --host <ct104> --multiquery
--
-- ssdf#104: policy-drift verdicts, one row per (intent commit, flow or
-- isolation) check, written by the drift collector. Rows form a per-server_id
-- SHA-256 hash chain (prev_hash/row_hash, same shape as ssdf.audit, the
-- canonical form lives in ssdf_mcp_query.drift_chain), so a verdict cannot be
-- rewritten or dropped without breaking linkage. No backfill: the chain starts
-- at the first row each writer inserts.
--
-- Insert-only writer: ssdf_drift gets INSERT and nothing else (no read-back, no
-- mutations). It cannot read back or change a verdict it wrote. The
-- verifier identity ssdf_audit_verify gets SELECT. ssdf_ro gets nothing, and
-- sql_guard refuses the table, so drift is not reachable via run_sql.
--
-- Retried inserts: non_replicated_deduplication_window is the same value 016
-- applies to ssdf.audit, set at creation. Writers send
-- insert_deduplication_token so a retried block is dropped server-side.
--
-- TTL 410 days, same retention as audit_evidence (023): covers a 13-month audit.
CREATE TABLE IF NOT EXISTS ssdf.policy_drift
(
    ts                   DateTime64(3, 'UTC'),
    server_id            String,
    intent_commit        String,
    flow_or_isolation_id String,
    verdict              LowCardinality(String),
    device               String,
    device_rule_ids      Array(String),
    evidence_ref         String,
    labmode              UInt8,
    prev_hash            String,
    row_hash             String
)
ENGINE = MergeTree
ORDER BY (server_id, ts)
TTL toDateTime(ts) + INTERVAL 410 DAY
SETTINGS non_replicated_deduplication_window = 10000;

CREATE USER IF NOT EXISTS ssdf_drift IDENTIFIED WITH sha256_password BY '${DRIFT_PW}';
GRANT INSERT ON ssdf.policy_drift TO ssdf_drift;

GRANT SELECT ON ssdf.policy_drift TO ssdf_audit_verify;
