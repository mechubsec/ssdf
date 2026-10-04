# SSDF ClickHouse Database

This directory contains ClickHouse DDL and configuration for SSDF.

## Migrations

- `001_events.sql` - Core events table
- `002_topology.sql` - Topology graph schema
- `003_topo_user.sql` - Read-only user for topology queries
- `004_entities.sql` - Entity table
- `005_entity_user.sql` - Read-only user for entity queries
- `006_observer_hostname.sql` - Observer hostname mapping
- `007_audit.sql` - Audit log table
- `008_public_views.sql` - Public views
- `009_audit_hash_chain.sql` - Hash chain for audit integrity
- `010_ro_settings_constraints.sql` - Read-only settings
- `011_entity_maint_user.sql` - Maintenance user for entities
- `012_backfill_paloalto_utc.sql.example` - Example backfill script (not auto-applied)
- `013_public_metrics.sql` - Public metrics tables
- `014_health_metrics.sql` - Health metrics tables
- `015_health_user.sql` - Health metrics user
- `016_audit_insert_dedup.sql` - Deduplication for audit inserts
- `017_audit_attribution.sql` - Audit attribution tracking
- `018_ssdf_ro_grants.sql` - Read-only grants
- `019_rule_usage_hourly.sql` - Hourly rule usage rollup
- `020_policy_versions.sql` - Policy version tracking
- `021_object_book_hash.sql` - Object-book hash tracking
- `022_audit_checkpoints.sql` - Signed audit-chain checkpoints
- `023_audit_evidence.sql` - Long-retention evidence tier
- `024_audit_ocsf_export.sql` - OCSF export for the audit chain
- `025_flow_tuples_daily.sql` - Daily flow-tuple rollup

Run migrations with: `python3 ../scripts/run_migrations.py` (see
`scripts/MIGRATION_RUNNER.md`). The `ssdf.migrations_applied` tracking table
is created by the runner itself, not by a numbered migration file, so a
fresh install always has somewhere to record migration 1's completion.
Migrations that create `CREATE USER ... BY '${VAR}'` service accounts (003,
005, 007, 008, 009, 011, 013, 015, 018, 019, 022-025) need the matching
`*_PW` environment variable set; the runner substitutes `${VAR}` /
`${VAR:-default}` placeholders itself and refuses to run if a required
variable is unset or empty. The full set of required variables (every
placeholder with no `:-default` across `infra/clickhouse/*.sql`) is:

```
ARCHIVER_PW, AUDIT_EXPORT_PW, AUDIT_PW, AUDIT_VERIFY_PW, CHECKPOINT_PW,
DEFINER_PW, ENTITY_MAINT_PW, ENTITY_PW, FLOWTUPLES_PW, HEALTH_PW,
OCSF_DEFINER_PW, PUBLIC_PW, PUBMETRICS_PW, RO_PW, RULEUSAGE_PW, TOPO_PW,
VIEW_PSEUDONYM_KEY_HI, VIEW_PSEUDONYM_KEY_LO
```

(`HEALTH_TTL_DAYS` has a default of 30 and is optional.)
`services/mcp-query/tests/test_run_migrations.py::test_readme_lists_every_required_placeholder`
fails if a new migration adds a placeholder without a matching README entry.

## systemd

### Single-Host Profile

The `ssdf-single-host.target` unit pulls in ClickHouse, the migration runner
and the MCP query service, in that order. It is a `.target`, not a service
with its own `ExecStart`: the ordering comes from each unit's own
`After=`/`Before=`/`Requires=`, so there is no single wrapper process whose
exit can be mistaken for "done" and tear the other two down (the
`ssdf-single-host.service` this replaced had that bug).

```bash
# Copy the service files to your system
sudo cp infra/clickhouse/ssdf-clickhouse.service /etc/systemd/system/
sudo cp infra/clickhouse/ssdf-migrate.service /etc/systemd/system/
sudo cp infra/clickhouse/ssdf-single-host.target /etc/systemd/system/
sudo cp services/mcp-query/infra/ssdf-mcp-query.service /etc/systemd/system/

# Create configuration directory and the migration runner's CH password,
# root-owned 0600 -- ssdf-migrate.service reads it via LoadCredential=, never
# from an env file or argv.
sudo mkdir -p /etc/ssdf
sudo install -m 0600 /dev/stdin /etc/ssdf/ch-migrate-password <<< "<your-password>"

# Per-migration secrets: every *_PW / VIEW_PSEUDONYM_KEY_* variable listed
# above, root-owned 0600. ssdf-migrate.service loads this via
# EnvironmentFile= before DynamicUser= drops privileges. Without it, a fresh
# install applies 001-002 and then aborts on the first migration that needs
# a service-account password (fail closed, by design).
sudo install -m 0600 /dev/stdin /etc/ssdf/migrate-secrets.env <<'EOF'
RO_PW=<password>
TOPO_PW=<password>
ENTITY_PW=<password>
ENTITY_MAINT_PW=<password>
AUDIT_PW=<password>
AUDIT_VERIFY_PW=<password>
AUDIT_EXPORT_PW=<password>
PUBLIC_PW=<password>
HEALTH_PW=<password>
PUBMETRICS_PW=<password>
RULEUSAGE_PW=<password>
DEFINER_PW=<password>
CHECKPOINT_PW=<password>
ARCHIVER_PW=<password>
OCSF_DEFINER_PW=<password>
FLOWTUPLES_PW=<password>
VIEW_PSEUDONYM_KEY_HI=<password>
VIEW_PSEUDONYM_KEY_LO=<password>
EOF

# Configure MCP query secrets (see services/mcp-query/infra/ssdf-mcp-query.service)
sudo tee /etc/ssdf-mcp/secrets.env <<EOF
...
EOF

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable ssdf-single-host.target
sudo systemctl start ssdf-single-host.target
```

### Individual Services

The single-host profile depends on:
- `ssdf-clickhouse.service` - ClickHouse database
- `ssdf-migrate.service` - idempotent migration runner, one-shot
- `ssdf-mcp-query.service` - MCP query service

## Configuration

See `scripts/MIGRATION_RUNNER.md` for migration runner usage.
