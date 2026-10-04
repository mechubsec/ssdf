#!/usr/bin/env python3
"""Idempotent ClickHouse migration runner.

Applies all pending migrations in numeric order. Safe to rerun.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

MIGRATIONS_DIR = Path(__file__).parent.parent / "infra" / "clickhouse"

_NUMBER_RE = re.compile(r"^(\d+)_.*\.sql$")
_PLACEHOLDER_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(:-([^}]*))?\}")

# The tracking table is created directly by the runner, not as a numbered
# migration: a fresh install has no row for any migration yet, so a numbered
# "migration 1 creates this table" would itself need to be recorded into a
# table that does not exist until it runs, and every subsequent run would
# reapply it and fail the same way (M-2). Keyed on the filename rather than a
# bare integer so two files that happen to share a numeric prefix cannot
# collapse onto the same tracking row (M-3) -- get_migration_files() also
# refuses outright on that collision, as defense in depth.
_ENSURE_TRACKING_TABLE_SQL = """
CREATE DATABASE IF NOT EXISTS ssdf;

CREATE TABLE IF NOT EXISTS ssdf.migrations_applied
(
    migration_file String,
    applied_at DateTime DEFAULT now()
)
ENGINE = ReplacingMergeTree
ORDER BY (migration_file);
""".strip()


class MigrationError(RuntimeError):
    """A migration-runner failure. Messages never include a password or a
    full command line -- only a migration/step name and an exit code."""


def get_migration_files() -> list[Path]:
    """Return every infra/clickhouse/NNN_*.sql file, sorted by (number, name).

    Refuses if two files share a numeric prefix rather than silently merging
    them onto one tracking row.
    """
    by_number: dict[int, Path] = {}
    for f in sorted(MIGRATIONS_DIR.glob("*.sql")):
        match = _NUMBER_RE.match(f.name)
        if not match:
            continue
        num = int(match.group(1))
        if num in by_number:
            raise MigrationError(
                f"migration number collision: {by_number[num].name} and "
                f"{f.name} both use prefix {num}"
            )
        by_number[num] = f
    return [by_number[num] for num in sorted(by_number)]


def substitute_placeholders(sql: str, source: str) -> str:
    """Resolve ``${VAR}`` / ``${VAR:-default}`` placeholders from the
    environment before the SQL is sent anywhere.

    Fails closed: a referenced variable that is unset or empty and has no
    default aborts the whole run before a single byte reaches
    clickhouse-client. The error names the missing variable, never a value.
    """
    missing: list[str] = []

    def _resolve(match: re.Match[str]) -> str:
        name = match.group(1)
        has_default = match.group(2) is not None
        value = os.environ.get(name)
        if value:
            return value
        if has_default:
            return match.group(3) or ""
        missing.append(name)
        return ""

    substituted = _PLACEHOLDER_RE.sub(_resolve, sql)
    if missing:
        names = ", ".join(sorted(set(missing)))
        raise MigrationError(f"{source}: missing required environment variable(s): {names}")
    return substituted


def clickhouse_cmd(*args: str, ch_host: str, ch_port: int, ch_user: str) -> list[str]:
    """Build a clickhouse-client argv. The password is never passed here: it
    reaches the child process only through the CLICKHOUSE_PASSWORD env var
    (see _run), so it never shows up in `ps` or a crash's argv dump."""
    return [
        "clickhouse-client",
        "--host",
        ch_host,
        "--port",
        str(ch_port),
        "--user",
        ch_user,
        *args,
    ]


def _run(step: str, cmd: list[str], ch_password: str, **kwargs) -> subprocess.CompletedProcess:
    """Run a clickhouse-client command. CH_PASSWORD is the single source of
    truth for the password; it is injected into the child's environment as
    CLICKHOUSE_PASSWORD (what clickhouse-client reads) and never appended to
    argv. On failure, raise with only the step name and exit code -- never
    the full command or captured output, which could echo the password back
    in a server error message."""
    env = dict(os.environ)
    if ch_password:
        env["CLICKHOUSE_PASSWORD"] = ch_password
    else:
        env.pop("CLICKHOUSE_PASSWORD", None)
    try:
        return subprocess.run(cmd, env=env, text=True, check=True, **kwargs)
    except subprocess.CalledProcessError as exc:
        raise MigrationError(f"{step} failed (clickhouse-client exit {exc.returncode})") from None
    except FileNotFoundError as exc:
        raise MigrationError(f"{step} failed: {exc.filename} not found on PATH") from None


def ensure_tracking_table(ch_host: str, ch_port: int, ch_user: str, ch_password: str) -> None:
    """Create ssdf.migrations_applied up front, before any migration is
    scanned or applied. See the module-level comment on
    _ENSURE_TRACKING_TABLE_SQL for why this cannot be migration 1 itself."""
    cmd = clickhouse_cmd(
        "--multiquery",
        "--query",
        _ENSURE_TRACKING_TABLE_SQL,
        ch_host=ch_host,
        ch_port=ch_port,
        ch_user=ch_user,
    )
    _run("create migrations_applied table", cmd, ch_password)


def get_applied_migrations(ch_host: str, ch_port: int, ch_user: str, ch_password: str) -> set[str]:
    """Query ClickHouse for already-applied migration filenames.

    Any client error here is fatal and propagates as a MigrationError: a
    transient connection failure must never be read as "nothing is applied
    yet", which would replay every GRANT and ALTER USER statement against a
    live deployment. The empty set is returned only when the query succeeds
    and genuinely has zero rows.
    """
    cmd = clickhouse_cmd(
        "--query",
        "SELECT migration_file FROM ssdf.migrations_applied ORDER BY migration_file",
        ch_host=ch_host,
        ch_port=ch_port,
        ch_user=ch_user,
    )
    result = _run("list applied migrations", cmd, ch_password, capture_output=True)
    return {line.strip() for line in result.stdout.strip().split("\n") if line.strip()}


def apply_migration(
    ch_host: str, ch_port: int, ch_user: str, ch_password: str, migration_file: Path
) -> None:
    """Substitute placeholders and apply one migration file."""
    sql = substitute_placeholders(migration_file.read_text(), migration_file.name)
    cmd = clickhouse_cmd("--multiquery", ch_host=ch_host, ch_port=ch_port, ch_user=ch_user)
    _run(f"apply {migration_file.name}", cmd, ch_password, input=sql)


def record_migration(
    ch_host: str, ch_port: int, ch_user: str, ch_password: str, migration_file: Path
) -> None:
    cmd = clickhouse_cmd(
        "--query",
        "INSERT INTO ssdf.migrations_applied (migration_file, applied_at) "
        f"VALUES ('{migration_file.name}', now())",
        ch_host=ch_host,
        ch_port=ch_port,
        ch_user=ch_user,
    )
    _run(f"record {migration_file.name}", cmd, ch_password)


def mark_baseline(
    ch_host: str,
    ch_port: int,
    ch_user: str,
    ch_password: str,
    migrations: list[Path],
    baseline: int,
) -> int:
    """Mark every migration numbered <= baseline as applied without running
    its SQL. For adopting the runner on a deployment whose schema already
    reflects those migrations (applied by hand before this runner existed)."""
    marked = 0
    for f in migrations:
        num = int(_NUMBER_RE.match(f.name).group(1))
        if num <= baseline:
            record_migration(ch_host, ch_port, ch_user, ch_password, f)
            print(f"  marked {f.name} as applied (baseline)")
            marked += 1
    return marked


def _parse_args(argv: list[str]) -> int | None:
    if not argv:
        return None
    if len(argv) == 2 and argv[0] == "--baseline":
        try:
            return int(argv[1])
        except ValueError as exc:
            raise SystemExit("--baseline requires an integer migration number") from exc
    raise SystemExit("usage: run_migrations.py [--baseline N]")


def main() -> int:
    """Main entry point."""
    baseline = _parse_args(sys.argv[1:])

    ch_host = os.environ.get("CH_HOST", "127.0.0.1")
    # clickhouse-client speaks the native protocol, which defaults to 9000 --
    # not the HTTP port (8123, CH_PORT) that mcp-query and the SQL-contract
    # job use. Keeping a separate variable means fixing one does not silently
    # break the other.
    ch_port = int(os.environ.get("CH_NATIVE_PORT", "9000"))
    ch_user = os.environ.get("CH_USER", "default")
    ch_password = os.environ.get("CH_PASSWORD", "")

    try:
        migrations = get_migration_files()
        if not migrations:
            print("No migration files found in", MIGRATIONS_DIR, file=sys.stderr)
            return 1

        ensure_tracking_table(ch_host, ch_port, ch_user, ch_password)

        if baseline is not None:
            marked = mark_baseline(ch_host, ch_port, ch_user, ch_password, migrations, baseline)
            print(f"Marked {marked} migration(s) up to {baseline} as applied")
            return 0

        applied = get_applied_migrations(ch_host, ch_port, ch_user, ch_password)
        pending = [f for f in migrations if f.name not in applied]

        if not pending:
            print("All migrations already applied")
            return 0

        print(f"Applying {len(pending)} pending migration(s)...")
        for migration_file in pending:
            print(f"Applying {migration_file.name}...")
            apply_migration(ch_host, ch_port, ch_user, ch_password, migration_file)
            record_migration(ch_host, ch_port, ch_user, ch_password, migration_file)
            print(f"  Applied {migration_file.name}")

        print(f"Successfully applied {len(pending)} migration(s)")
        return 0
    except MigrationError as exc:
        print(f"migration runner failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
