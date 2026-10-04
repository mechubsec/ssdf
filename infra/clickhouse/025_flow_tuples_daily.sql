-- infra/clickhouse/025_flow_tuples_daily.sql
-- MEC-1639 (task B of MEC-570, pre-change impact analysis): daily rollup of
-- ssdf.events into effective flow tuples, keyed for device+zone-pair
-- locality. Modeled directly on 019_rule_usage_hourly.sql (MEC-566).
--
-- Why this table exists (change-impact-scope doc on MEC-986, §2): raw
-- ssdf.events is ORDER BY (tenant_id, timestamp, event_action), so a query
-- scoped to one device/zone-pair still reads every granule in the window,
-- and the fields change_impact needs for NAT-aware matching (Junos
-- `ext['nat-destination-address']`, PAN-OS `ext['panw.panos.application']`)
-- force a read of the whole `ext` Map. Ordering by
-- (tenant_id, observer_hostname, ingress_zone, egress_zone, day, ...) lets
-- ClickHouse prune to one device and zone-pair via the primary index, and
-- paying the `ext` extraction cost once per rollup run instead of on every
-- query.
--
-- Effective tuple (doc §1.3): source IP is always pre-NAT for both vendors.
-- Destination IP is `ext['nat-destination-address']` for Junos when present
-- and not 0.0.0.0 (Junos applies static/destination NAT before the policy
-- lookup), else `destination_ip`; PAN-OS always matches pre-NAT, so
-- `destination_ip` is already correct there. Source port is dropped --
-- ephemeral, and the main cardinality driver. See
-- services/policy/src/ssdf_policy/flow_tuples_rollup.py for the query and
-- its unit-tested per-vendor helpers.
--
-- ReplacingMergeTree(inserted_at), same reasoning as rule_usage_hourly: the
-- rollup job recomputes a trailing window of whole days on every run so
-- late-arriving events land on the next pass. A rerun with the same key
-- overwrites rather than double-counts. Readers must query with FINAL (or
-- argMax over inserted_at).
--
-- TTL 90 days (doc §4 default; NOT yet confirmed against a measured
-- sessions/day figure -- see the PR for MEC-1639, which records what was
-- actually measured and flags if it wasn't). Adjust with
-- `ALTER TABLE ssdf.flow_tuples_daily MODIFY TTL day + INTERVAL <n> DAY;`
-- if the measured volume changes the recommendation.
--
-- Least-privilege writer, separate from ssdf_entity and ssdf_ruleusage: this
-- rollup reads ssdf.events and writes only this table. Inject the password
-- before applying (never commit the real value):
--   FLOWTUPLES_PW="$CH_FLOWTUPLES_PASSWORD" envsubst < 025_flow_tuples_daily.sql \
--     | clickhouse-client --host <ct104> --multiquery
CREATE TABLE IF NOT EXISTS ssdf.flow_tuples_daily
(
    tenant_id         LowCardinality(String) DEFAULT 't_main',
    observer_hostname LowCardinality(String) DEFAULT '',
    ingress_zone      LowCardinality(String),
    egress_zone       LowCardinality(String),
    day               Date,
    src_ip            Nullable(IPv4),
    dst_ip_eff        Nullable(IPv4),
    transport         LowCardinality(String),
    dst_port          Nullable(UInt16),
    app               LowCardinality(String) DEFAULT '',
    provider          LowCardinality(String),
    sessions          UInt64,
    bytes             UInt64,
    first_seen        DateTime64(3, 'UTC'),
    last_seen         DateTime64(3, 'UTC'),
    logged_rules      Array(String),
    outcomes          Array(LowCardinality(String)),
    inserted_at       DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree(inserted_at)
ORDER BY (tenant_id, observer_hostname, ingress_zone, egress_zone, day, src_ip, dst_ip_eff, transport, dst_port, app)
TTL day + INTERVAL 90 DAY
-- src_ip/dst_ip_eff are Nullable(IPv4), same reasoning as ssdf.events: IPv6
-- flows keep the typed column null rather than failing the whole insert
-- batch (vector.toml comment at the IPv4 guard). Nullable columns in the
-- sorting key need this setting (CREATE fails with ILLEGAL_COLUMN
-- otherwise, confirmed against a local ClickHouse 24.8).
SETTINGS allow_nullable_key = 1;

CREATE USER IF NOT EXISTS ssdf_flowtuples IDENTIFIED WITH sha256_password BY '${FLOWTUPLES_PW}';
GRANT SELECT ON ssdf.events TO ssdf_flowtuples;
GRANT INSERT, SELECT ON ssdf.flow_tuples_daily TO ssdf_flowtuples;

-- Sovereign read access (the change_impact evaluator, task C of MEC-570).
GRANT SELECT ON ssdf.flow_tuples_daily TO ssdf_ro;
