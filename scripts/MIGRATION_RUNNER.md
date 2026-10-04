# Migration Runner

The `run_migrations.py` script applies all pending ClickHouse migrations in numeric order.

## Usage

```bash
export CH_HOST=<host>
export CH_PORT=<port>
export CH_USER=<user>
export CH_PASSWORD=<password>
python3 scripts/run_migrations.py
```

## Behavior

- Scans `infra/clickhouse/` for `.sql` files matching pattern `NNN_*.sql`
- Queries `ssdf.migrations_applied` table for already-applied migrations
- Applies only pending migrations in numeric order
- Records each applied migration with timestamp
- Safe to run multiple times (idempotent)

## Migration Tracking Table

Migrations are tracked in the `ssdf.migrations_applied` table (created by migration 021):

```sql
CREATE TABLE IF NOT EXISTS ssdf.migrations_applied
(
    migration_number UInt32,
    applied_at DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree
ORDER BY (migration_number);
```

## Adding New Migrations

1. Create a new `.sql` file in `infra/clickhouse/` with the next numeric prefix
2. The migration runner will automatically pick it up on subsequent runs
