-- infra/clickhouse/026_events_ocsf_export.sql
--
-- Apply: inject CH_OCSF_DEFINER_PASSWORD and CH_EVENTS_EXPORT_PASSWORD before
-- applying (never commit real values). The `: "${VAR:?}"` guards abort on
-- an unset/empty source variable instead of letting envsubst substitute an
-- empty string, which would otherwise create a passworded-by-empty-string user.
--   : "${CH_OCSF_DEFINER_PASSWORD:?}" "${CH_EVENTS_EXPORT_PW:?}" \
--     && OCSF_DEFINER_PW="$CH_OCSF_DEFINER_PASSWORD" EVENTS_EXPORT_PW="$CH_EVENTS_EXPORT_PASSWORD" \
--     envsubst < 026_events_ocsf_export.sql \
--     | clickhouse-client --host <ct104> --multiquery
--
-- MEC-571: an export projection of ssdf.events for consumers that want
-- network event data in an OCSF-flavoured shape. This view maps to OCSF
-- Network Activity (class 4001), the standard class for network flow and
-- connection events.
--
-- DEVIATIONS FROM OCSF 1.9, STATED EXPLICITLY:
-- 1. OCSF 1.9 specifies class_uid 4001 for Network Activity, but ClickHouse
--    views cannot expose metadata fields like class_uid directly. We use
--    class_name = 'Network Activity (mapped-for-export; class 4001)' to
--    indicate the intended mapping.
-- 2. OCSF network_activity has fields like protocol, network_protocol, and
--    ip_protocols (array). We map network_transport -> protocol and use
--    arrayJoin to expand ip_protocols if present.
-- 3. OCSF actor.user.user_type -> we set actor_user_type = 'service' since
--    events.user_name represents a service account or tool identity.
-- 4. OCSF network_activity has request_response_id. We map event_id -> this
--    field to provide a traceable correlation ID.
--
-- Source: events (30-day TTL) - this is the operational event stream. For
-- long-horizon retention, events are archived elsewhere (see event_archiver).
-- This view uses the raw events table directly since the 30-day TTL is
-- acceptable for OCSF export use cases (typically operational monitoring).
--
-- Computed fields:
-- - src_ip, dst_ip: IPv4 addresses (Nullable)
-- - src_port, dst_port: transport ports (Nullable UInt16)
-- - protocol: mapped from network_transport (LowCardinality String)
-- - src_bytes, dst_bytes: mapped from source_bytes, destination_bytes
-- - activity_name: derived from event_action for clarity
-- - status: mapped from event_outcome (success, failure, etc.)

CREATE USER IF NOT EXISTS ssdf_events_ocsf_definer IDENTIFIED WITH sha256_password BY '${OCSF_DEFINER_PW}';
GRANT SELECT ON ssdf.events TO ssdf_events_ocsf_definer;

CREATE VIEW IF NOT EXISTS ssdf.events_ocsf_export
    DEFINER = ssdf_events_ocsf_definer SQL SECURITY DEFINER
AS
SELECT
    toUnixTimestamp64Milli(e.timestamp)            AS time,
    'Network Activity (mapped-for-export; class 4001)' AS class_name,
    e.event_action                                 AS activity_name,
    e.user_name                                    AS actor_user_name,
    'service'                                      AS actor_user_type,
    e.event_outcome                                AS status,
    e.tenant_id                                    AS cloud_account_id,
    e.source_ip                                    AS src_ip,
    e.source_port                                  AS src_port,
    e.destination_ip                               AS dst_ip,
    e.destination_port                             AS dst_port,
    e.network_transport                            AS protocol,
    e.source_bytes                                 AS src_bytes,
    e.destination_bytes                            AS dst_bytes,
    e.network_bytes                                AS total_bytes,
    e.rule_name                                    AS rule_name,
    e.observer_ingress_zone                        AS src_security_zone,
    e.observer_egress_zone                         AS dst_security_zone,
    e.event_id                                     AS request_response_id,
    e.event_id                                     AS correlation_id,
    e.ext                                          AS metadata,
    e.event_kind                                   AS event_category,
    e.event_provider                               AS event_provider
FROM ssdf.events AS e;

-- ssdf_events_export: the ONLY identity with read access to the export view.
-- Deliberately not granted to ssdf_ro -- event content stays out of the
-- general query surface, consistent with ssdf.audit's access model.
--
-- Granted on the VIEW ONLY: with SQL SECURITY DEFINER set above, the view's
-- own SELECT runs as ssdf_events_ocsf_definer, not as the querying user, so
-- ssdf_events_export needs no base-table grant at all -- and in particular
-- cannot read events' columns the view leaves out on purpose (raw, ext).
CREATE USER IF NOT EXISTS ssdf_events_export IDENTIFIED WITH sha256_password BY '${EVENTS_EXPORT_PW}';
GRANT SELECT ON ssdf.events_ocsf_export TO ssdf_events_export;
