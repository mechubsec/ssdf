-- infra/clickhouse/027_events_ocsf_authentication.sql
--
-- Apply: inject CH_OCSF_DEFINER_PASSWORD and CH_EVENTS_EXPORT_PASSWORD before
-- applying (never commit real values). The `: "${VAR:?}"` guards abort on
-- an unset/empty source variable instead of letting envsubst substitute an
-- empty string, which would otherwise create a passworded-by-empty-string user.
--   : "${CH_OCSF_DEFINER_PASSWORD:?}" "${CH_EVENTS_EXPORT_PW:?}" \
--     && OCSF_DEFINER_PW="$CH_OCSF_DEFINER_PASSWORD" EVENTS_EXPORT_PW="$CH_EVENTS_EXPORT_PASSWORD" \
--     envsubst < 027_events_ocsf_authentication.sql \
--     | clickhouse-client --host <ct104> --multiquery
--
-- MEC-571: an export projection of ssdf.events for authentication events,
-- mapped to OCSF Authentication (class 4002).
--
-- DEVIATIONS FROM OCSF 1.9, STATED EXPLICITLY:
-- 1. OCSF 1.9 specifies class_uid 4002 for Authentication, but ClickHouse
--    views cannot expose metadata fields like class_uid directly. We use
--    class_name = 'Authentication (mapped-for-export; class 4002)' to
--    indicate the intended mapping.
-- 2. OCSF authentication has authentication_result (success, failure, etc.),
--    authentication_type (password, mfa, etc.), and credentials_used (array).
--    We map event_outcome -> authentication_result and event_category ->
--    authentication_type where applicable.
-- 3. OCSF actor.user.user_type -> we set actor_user_type = 'service' since
--    events.user_name represents a service account or tool identity.
--
-- Source: events (30-day TTL) - only rows with event_category containing
-- "authentication" or event_action containing "auth" are included. For
-- long-horizon retention, events are archived elsewhere.
--
-- Computed fields:
-- - authentication_result: mapped from event_outcome
-- - authentication_type: derived from event_category where available
-- -_actor_user_type: set to 'service' (events don't have user-level auth)
-- - authentication_request_id: mapped from event_id
-- - src_ip, dst_ip: available where events have network data

CREATE USER IF NOT EXISTS ssdf_events_ocsf_definer IDENTIFIED WITH sha256_password BY '${OCSF_DEFINER_PW}';
GRANT SELECT ON ssdf.events TO ssdf_events_ocsf_definer;

-- Filter to authentication-related events: either event_category contains
-- 'authentication' or event_action contains 'auth' (case-insensitive).
CREATE VIEW IF NOT EXISTS ssdf.events_ocsf_authentication_export
    DEFINER = ssdf_events_ocsf_definer SQL SECURITY DEFINER
AS
SELECT
    toUnixTimestamp64Milli(e.timestamp)                    AS time,
    'Authentication (mapped-for-export; class 4002)'      AS class_name,
    e.event_action                                        AS activity_name,
    e.user_name                                           AS actor_user_name,
    'service'                                             AS actor_user_type,
    e.event_outcome                                       AS authentication_result,
    arrayJoin(e.event_category)                           AS authentication_type,
    e.source_ip                                           AS src_ip,
    e.destination_ip                                      AS dst_ip,
    e.event_id                                            AS authentication_request_id,
    e.event_id                                            AS correlation_id,
    e.tenant_id                                           AS cloud_account_id,
    e.ext                                                 AS metadata,
    e.event_provider                                      AS event_provider
FROM ssdf.events AS e
WHERE
    -- Authentication events: either the category contains 'authentication'
    -- or the action contains 'auth' (case-insensitive matching)
    'authentication' IN e.event_category
    OR lower(e.event_action) LIKE '%auth%'
    OR lower(e.event_kind) LIKE '%auth%';

-- ssdf_events_export: the ONLY identity with read access to the export view.
-- Deliberately not granted to ssdf_ro -- event content stays out of the
-- general query surface, consistent with ssdf.audit's access model.
--
-- Granted on the VIEW ONLY: with SQL SECURITY DEFINER set above, the view's
-- own SELECT runs as ssdf_events_ocsf_definer, not as the querying user, so
-- ssdf_events_export needs no base-table grant at all -- and in particular
-- cannot read events' columns the view leaves out on purpose (raw, ext).
CREATE USER IF NOT EXISTS ssdf_events_export IDENTIFIED WITH sha256_password BY '${EVENTS_EXPORT_PW}';
GRANT SELECT ON ssdf.events_ocsf_authentication_export TO ssdf_events_export;
