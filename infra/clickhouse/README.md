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
- `021_migrations_tracking.sql` - Migration tracking table

Run migrations with: `python3 ../scripts/run_migrations.py`

## systemd

### Single-Host Profile

The `ssdf-single-host.service`unit starts ClickHouse and all SSDF services:

```bash
# Copy the service files to your system
sudo cp infra/clickhouse/ssdf-clickhouse.service /etc/systemd/system/
sudo cp infra/clickhouse/ssdf-single-host.service /etc/systemd/system/
sudo cp services/mcp-query/infra/ssdf-mcp-query.service /etc/systemd/system/

# Create configuration directory
sudo mkdir -p /etc/ssdf
sudo cp infra/clickhouse/ssdf-clickhouse.service /etc/systemd/system/
sudo cp services/mcp-query/infra/ssdf-mcp-query.service /etc/systemd/system/

# Configure secrets
sudo tee /etc/ssdf/single-host.env <<EOF
CH_PASSWORD=<your-password>
EOF

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable ssdf-single-host
sudo systemctl start ssdf-single-host
```

### Individual Services

The single-host profile depends on:
- `ssdf-clickhouse.service` - ClickHouse database
- `ssdf-mcp-query.service` - MCP query service

## Configuration

See `scripts/MIGRATION_RUNNER.md` for migration runner usage.
