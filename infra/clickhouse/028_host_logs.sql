-- infra/clickhouse/028_host_logs.sql
--
-- Host logs: warning-and-worse system logs from Linux hosts (journald via a
-- Vector agent, rsyslog), Proxmox nodes and Junos system logs. Operational
-- diagnostics, not security events, so they live in their own table rather
-- than ssdf.events (no OCSF mapping, no tenant, no entity resolution).
-- Vector filters at ingest (vector.toml hl_keep) so only errors, unit
-- failures and coredumps are stored. 30-day TTL, no definer user: Vector
-- writes with its existing ClickHouse identity.
--
-- This migration creates no users, so it needs no *_PW variable.

CREATE TABLE IF NOT EXISTS ssdf.host_logs (
    timestamp DateTime64(3, 'UTC'),
    host      LowCardinality(String),
    source    LowCardinality(String),   -- journald | syslog | junos | proxmox
    unit      LowCardinality(String),   -- systemd unit, else syslog app-name
    severity  UInt8,                    -- syslog 0-7
    message   String,                   -- capped at 4096 chars at ingest
    raw       String
) ENGINE = MergeTree
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (timestamp, host)
TTL toDateTime(timestamp) + INTERVAL 30 DAY;

-- Liveness: every line reaching the host-log taps (any severity) is counted
-- per minute, so a sender that logs nothing at warning+ still shows as
-- alive. host_log_lines is a Null-engine landing table that only feeds the
-- materialized view, so the per-line rows are never stored.
CREATE TABLE IF NOT EXISTS ssdf.host_log_lines (
    host   LowCardinality(String),
    source LowCardinality(String)
) ENGINE = Null;

CREATE TABLE IF NOT EXISTS ssdf.host_log_senders (
    minute DateTime('UTC'),
    host   LowCardinality(String),
    source LowCardinality(String),
    lines  UInt64
) ENGINE = SummingMergeTree
ORDER BY (host, source, minute)
TTL minute + INTERVAL 30 DAY;

CREATE MATERIALIZED VIEW IF NOT EXISTS ssdf.host_log_senders_mv TO ssdf.host_log_senders AS
SELECT toStartOfMinute(now()) AS minute, host, source, count() AS lines
FROM ssdf.host_log_lines
GROUP BY host, source;

-- Sovereign read access. Not in sql_guard's blocked list: these hold no
-- audit or pseudonymised data.
GRANT SELECT ON ssdf.host_logs TO ssdf_ro;
GRANT SELECT ON ssdf.host_log_senders TO ssdf_ro;
