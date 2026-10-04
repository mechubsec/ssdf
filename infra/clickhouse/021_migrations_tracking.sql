-- Track applied migrations idempotently
CREATE DATABASE IF NOT EXISTS ssdf;

CREATE TABLE IF NOT EXISTS ssdf.migrations_applied
(
    migration_number UInt32,
    applied_at DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree
ORDER BY (migration_number);
