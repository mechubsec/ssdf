-- infra/clickhouse/023_audit_evidence.sql
--
-- Apply (same envsubst pattern as 008_public_views.sql): inject ARCHIVER_PW
-- before applying (never commit a real value). The
-- `: "${CH_ARCHIVER_PASSWORD:?}"` guard aborts on an unset/empty source
-- variable instead of letting envsubst substitute an empty string, which
-- would otherwise create a passworded-by-empty-string user with INSERT on
-- audit_evidence:
--   : "${CH_ARCHIVER_PASSWORD:?}" && ARCHIVER_PW="$CH_ARCHIVER_PASSWORD" \
--     envsubst < 023_audit_evidence.sql \
--     | clickhouse-client --host <ct104> --multiquery
--
-- MEC-565: retention-safe evidence tier. ssdf.audit (007_audit.sql) carries a
-- 90-day TTL -- fine for operational use, not for a 13-month audit. This
-- table is a durable archive of audit rows, populated by scripts/archive_audit.py
-- *before* they age out of ssdf.audit, so coverage survives well past a year.
--
-- Same shape as ssdf.audit (007, 009, 017) so a row copies over verbatim --
-- the hash chain columns travel with it unchanged, so a row archived here
-- still verifies against the same row_hash it had in ssdf.audit. This table
-- does not maintain its own chain; it is a durable copy of rows that were
-- already chained and (optionally) checkpointed in ssdf.audit.
--
-- TTL 410 days: 400 is the acceptance floor (a 13-month audit needs ~395
-- days of coverage); 410 gives the archiver job slack to run late without a
-- row falling through both tables' retention windows.
CREATE TABLE IF NOT EXISTS ssdf.audit_evidence
(
    ts           DateTime64(3, 'UTC'),
    principal    LowCardinality(String),
    tier         LowCardinality(String),
    tool         LowCardinality(String),
    args         String,
    data_classes Array(LowCardinality(String)),
    decision     LowCardinality(String),
    row_count    UInt32,
    error        String,
    client_name  String DEFAULT '',
    model_id     String DEFAULT '',
    actor_type   String DEFAULT '',
    prev_hash    String DEFAULT '',
    row_hash     String DEFAULT '',
    archived_at  DateTime64(3, 'UTC') DEFAULT now64(3, 'UTC')
)
ENGINE = MergeTree
ORDER BY (ts, principal)
TTL toDateTime(ts) + INTERVAL 410 DAY;

-- ssdf_archiver: scripts/archive_audit.py's identity. SELECT on ssdf.audit to
-- read rows due for archiving, INSERT+SELECT on audit_evidence -- SELECT so
-- the archiver can skip rows it already copied (by row_hash) on a re-run,
-- making the job idempotent rather than relying on dedup tokens alone.
-- Bulk read access to archived audit content for reporting/export purposes
-- stays scoped to 024_audit_ocsf_export.sql's ssdf_audit_export identity, not
-- opened to ssdf_ro here.
CREATE USER IF NOT EXISTS ssdf_archiver IDENTIFIED WITH sha256_password BY '${ARCHIVER_PW}';
GRANT SELECT ON ssdf.audit TO ssdf_archiver;
GRANT INSERT, SELECT ON ssdf.audit_evidence TO ssdf_archiver;

-- ssdf_audit_verify (verify_audit.py) and ssdf_checkpoint
-- (scripts/checkpoint_audit.py, 022_audit_checkpoints.sql) both need to read
-- audit_evidence rows: once a dangling predecessor's own row has aged out of
-- ssdf.audit, the nearest checkpoint head rarely matches it directly, and
-- the evidence tier is where the rows between the two still live. This
-- grant is read-only and limited to these two existing read identities;
-- ssdf_ro remains excluded.
GRANT SELECT ON ssdf.audit_evidence TO ssdf_audit_verify;
GRANT SELECT ON ssdf.audit_evidence TO ssdf_checkpoint;
