# Migration Runner

The `run_migrations.py` script applies all pending ClickHouse migrations in
numeric order.

## Usage

```bash
export CH_HOST=<host>
export CH_NATIVE_PORT=<native-protocol-port>   # default 9000, NOT the HTTP port
export CH_USER=<user>
export CH_PASSWORD=<password>
python3 scripts/run_migrations.py
```

`CH_NATIVE_PORT` is deliberately separate from `CH_PORT`, which other
services (mcp-query, the SQL-contract job) use for ClickHouse's HTTP
interface (default 8123). `clickhouse-client` speaks the native protocol,
whose default is 9000; reusing `CH_PORT` here would point the runner at the
wrong port by default.

The password is read once from `CH_PASSWORD` and passed to `clickhouse-client`
only through the `CLICKHOUSE_PASSWORD` environment variable of the child
process -- never on the command line -- so it does not appear in `ps` output
or in a crash traceback's argv dump.

### Adopting an existing deployment

For a ClickHouse instance whose schema already reflects some migrations
(applied by hand before this runner existed), mark them as applied without
re-running their SQL:

```bash
python3 scripts/run_migrations.py --baseline 020
```

This records every migration numbered 20 and below as applied and exits.
Run it once, then run the plain form above to apply anything newer.

## Behavior

- Scans `infra/clickhouse/` for `.sql` files matching pattern `NNN_*.sql`,
  sorted by `(number, filename)`. Refuses to run at all if two files share a
  numeric prefix, rather than silently merging them onto one tracking row.
- Creates the `ssdf.migrations_applied` tracking table itself, before
  scanning for pending migrations -- it is not a numbered migration, since a
  fresh install would then need to record migration 1 into a table that
  migration 1 itself was supposed to create.
- Substitutes `${VAR}` / `${VAR:-default}` placeholders in each migration's
  SQL from the environment before sending anything to `clickhouse-client`.
  Several migrations (`CREATE USER ... IDENTIFIED ... BY '${FOO_PW}'`) rely on
  this. **Fails closed**: if a placeholder has no default and the matching
  variable is unset or empty, the runner aborts before applying that
  migration and names the missing variable (never its value).
- Queries `ssdf.migrations_applied` for already-applied migration filenames.
  Any error talking to ClickHouse here is fatal -- it is never treated as
  "nothing is applied yet", which would replay every `GRANT`/`ALTER USER`
  statement against a live deployment on a transient connection blip.
- Applies only pending migrations, in order, and records each one
  immediately after it runs.
- Safe to run multiple times (idempotent), given migrations that are
  themselves idempotent (`IF NOT EXISTS`, etc).

## Migration Tracking Table

Migrations are tracked in the `ssdf.migrations_applied` table, created by the
runner on every invocation (`CREATE TABLE IF NOT EXISTS`):

```sql
CREATE TABLE IF NOT EXISTS ssdf.migrations_applied
(
    migration_file String,
    applied_at DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree
ORDER BY (migration_file);
```

Rows are keyed on the full filename rather than the bare numeric prefix, so a
future numbering collision cannot cause two different migrations to share one
tracking row (the runner also refuses outright if it finds one, see above).

## Adding New Migrations

1. Create a new `.sql` file in `infra/clickhouse/` with the next numeric
   prefix. Check `infra/clickhouse/README.md` for the current highest number
   first -- the runner refuses to run if your new file collides with one
   already on `main`.
2. The migration runner will automatically pick it up on subsequent runs.
