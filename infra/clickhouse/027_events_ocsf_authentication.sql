-- infra/clickhouse/027_events_ocsf_authentication.sql
--
-- Apply: inject CH_EVENTS_OCSF_DEFINER_PASSWORD and CH_EVENTS_EXPORT_PASSWORD
-- before applying (never commit real values). The `: "${VAR:?}"` guards abort
-- on an unset/empty source variable instead of letting envsubst substitute an
-- empty string, which would otherwise create a passworded-by-empty-string user.
--   : "${CH_EVENTS_OCSF_DEFINER_PASSWORD:?}" "${CH_EVENTS_EXPORT_PASSWORD:?}" \
--     && EVENTS_OCSF_DEFINER_PW="$CH_EVENTS_OCSF_DEFINER_PASSWORD" EVENTS_EXPORT_PW="$CH_EVENTS_EXPORT_PASSWORD" \
--     envsubst < 027_events_ocsf_authentication.sql \
--     | clickhouse-client --host <ct104> --multiquery
--
-- Same ssdf_events_ocsf_definer identity as 026 (one definer per source
-- table is enough); its password is CH_EVENTS_OCSF_DEFINER_PASSWORD, kept
-- distinct from 024's CH_OCSF_DEFINER_PASSWORD since they are different
-- privilege domains.
--
-- MEC-571: an export projection of ssdf.events for authentication events,
-- mapped to OCSF Authentication (class 4002).
--
-- DEVIATIONS FROM OCSF 1.9, STATED EXPLICITLY:
-- 1. We emit class_uid as a literal (4002) alongside class_name, since a
--    ClickHouse view can project a constant column directly.
-- 2. OCSF authentication has authentication_type (password, mfa, etc.).
--    events carries no sub-type signal for this, so authentication_type is
--    a constant ('unspecified'); activity_name (event_action) still carries
--    the per-event detail (login, logout, auth_failure, ...).
-- 3. OCSF actor.user.user_type -> we set actor_user_type = 'service' since
--    events.user_name represents a service account or tool identity, not a
--    verified human user. This is a stand-in, not a verified mapping: SRX
--    user-firewall and PAN-OS srcuser can carry human identities.
--
-- Source: events (30-day TTL) - only rows whose event_category array
-- contains 'authentication' are included. We filter on category alone (not
-- a substring match on event_action/event_kind): matching text like "auth"
-- also matches unrelated actions such as "unauthorized_app" or
-- "authorization_change". For long-horizon retention, events are archived
-- elsewhere.
--
-- Computed fields:
-- - authentication_result: mapped from event_outcome
-- - authentication_type: constant, see deviation 2 above
-- - actor_user_type: set to 'service' (events don't have user-level auth)
-- - authentication_request_id: mapped from event_id
-- - src_ip, dst_ip: available where events have network data
--
-- `ext` and `raw` are deliberately NOT projected: they are the ssdf.events
-- columns most likely to carry attacker-influenceable or device-internal
-- text, and an OCSF export view exists to send events to an external SIEM.
-- Keep them out of this view rather than widening what leaves the box.

CREATE USER IF NOT EXISTS ssdf_events_ocsf_definer IDENTIFIED WITH sha256_password BY '${EVENTS_OCSF_DEFINER_PW}';
GRANT SELECT ON ssdf.events TO ssdf_events_ocsf_definer;

-- Filter to authentication-related events: event_category contains
-- 'authentication'. No arrayJoin -- expanding event_category would produce
-- one output row per category for any multi-category event, duplicating it
-- under every category it carries.
CREATE VIEW IF NOT EXISTS ssdf.events_ocsf_authentication_export
    DEFINER = ssdf_events_ocsf_definer SQL SECURITY DEFINER
AS
SELECT
    toUnixTimestamp64Milli(e.timestamp)                    AS time,
    4002                                                    AS class_uid,
    'Authentication (mapped-for-export, class 4002)'      AS class_name,
    e.event_action                                        AS activity_name,
    e.user_name                                           AS actor_user_name,
    'service'                                             AS actor_user_type,
    e.event_outcome                                       AS authentication_result,
    'unspecified'                                          AS authentication_type,
    e.source_ip                                           AS src_ip,
    e.destination_ip                                      AS dst_ip,
    e.event_id                                            AS authentication_request_id,
    e.event_id                                            AS correlation_id,
    e.tenant_id                                           AS cloud_account_id,
    e.event_provider                                      AS event_provider
FROM ssdf.events AS e
WHERE has(e.event_category, 'authentication');

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
