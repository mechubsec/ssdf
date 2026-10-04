-- infra/clickhouse/021_object_book_hash.sql
-- MEC-992 (task A of MEC-570, pre-change impact analysis): append-only history
-- of resolved address/application/service object books, one row per device
-- per content change. Mirrors 020_policy_versions.sql exactly -- INSERT-only,
-- a row is appended only when the collected object book's content hash
-- differs from the last known hash for that (provider, device_name); see
-- services/policy/src/ssdf_policy/object_book.py (pure diff, no I/O).
--
-- This is the table task B/C of MEC-570 calibrate flow-to-rule matching
-- against: a rule's own content can be unchanged while what it matches
-- shifts (an address-set gains a member), and that shift has to be visible
-- as its own history line, not folded into policy_versions.
--
-- No TTL, same reasoning as policy_versions: this is change history, not a
-- high-volume log.
CREATE TABLE IF NOT EXISTS ssdf.object_book_hash
(
    tenant_id    LowCardinality(String) DEFAULT 't_main',
    provider     LowCardinality(String),
    device_name  LowCardinality(String),
    valid_from   DateTime64(3, 'UTC'),
    content_hash String,
    object_book  String  -- JSON; resolved addresses/applications/services for this device at valid_from
)
ENGINE = MergeTree
ORDER BY (tenant_id, provider, device_name, valid_from);

-- Same writer identity as policy_versions: needs SELECT to diff a
-- newly-collected object book against its last known hash before deciding
-- whether to append. No ALTER DELETE grant to anyone, ever.
GRANT INSERT, SELECT ON ssdf.object_book_hash TO ssdf_entity;

-- Sovereign read access (the change_impact evaluator, task C of MEC-570).
GRANT SELECT ON ssdf.object_book_hash TO ssdf_ro;
