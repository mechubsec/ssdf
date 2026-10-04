#!/usr/bin/env python3
"""Idempotent ClickHouse migration runner.

Applies all pending migrations in numeric order. Safe to rerun.
"""

import os
import re
import subprocess
import sys
from pathlib import Path

# Configuration
MIGRATIONS_DIR = Path(__file__).parent.parent / "infra" / "clickhouse"
MIGRATION_TABLE_QUERY = """
SELECT count() FROM system.tables 
WHERE database = 'ssdf' AND name = 'migrations_applied'
"""


def get_migration_files() -> list[Path]:
    """Return all .sql migration files sorted by numeric prefix."""
    migrations = []
    pattern = re.compile(r"^(\d+)_.*\.sql$")
    for f in MIGRATIONS_DIR.glob("*.sql"):
        match = pattern.match(f.name)
        if match:
            migrations.append((int(match.group(1)), f))
    migrations.sort(key=lambda x: x[0])
    return [m[1] for m in migrations]


def clickhouse_cmd(
    *args: str, ch_host: str, ch_port: int, ch_user: str, ch_password: str = ""
) -> list[str]:
    """Build a clickhouse-client command with authentication."""
    cmd = [
        "clickhouse-client",
        "--host",
        ch_host,
        "--port",
        str(ch_port),
        "--user",
        ch_user,
    ]
    if ch_password:
        cmd.extend(["--password", ch_password])
    cmd.extend(args)
    return cmd


def get_applied_migrations(
    ch_host: str, ch_port: int, ch_user: str, ch_password: str = ""
) -> set[int]:
    """Query ClickHouse for applied migrations."""
    # First check if the migrations table exists
    check_table_cmd = clickhouse_cmd(
        "--query",
        MIGRATION_TABLE_QUERY.strip(),
        ch_host=ch_host,
        ch_port=ch_port,
        ch_user=ch_user,
        ch_password=ch_password,
    )
    try:
        result = subprocess.run(check_table_cmd, capture_output=True, text=True, check=True)
        table_exists = result.stdout.strip() == "1"
    except subprocess.CalledProcessError:
        # Table doesn't exist yet, no migrations applied
        return set()

    if not table_exists:
        return set()

    # Query applied migration numbers
    query = """
    SELECT migration_number FROM ssdf.migrations_applied
    ORDER BY migration_number
    """
    result = subprocess.run(
        clickhouse_cmd(
            "--query",
            query,
            ch_host=ch_host,
            ch_port=ch_port,
            ch_user=ch_user,
            ch_password=ch_password,
        ),
        capture_output=True,
        text=True,
        check=True,
    )
    applied = set()
    for line in result.stdout.strip().split("\n"):
        if line.strip():
            applied.add(int(line.strip()))
    return applied


def apply_migration(ch_host: str, ch_port: int, ch_user: str, migration_file: Path) -> None:
    """Apply a single migration file."""
    with open(migration_file) as f:
        sql = f.read()

    cmd = [
        "clickhouse-client",
        "--host",
        ch_host,
        "--port",
        str(ch_port),
        "--user",
        ch_user,
        "--multiquery",
    ]
    password = os.environ.get("CLICKHOUSE_PASSWORD", "")
    if password:
        cmd.extend(["--password", password])
    subprocess.run(cmd, input=sql, text=True, check=True)


def main() -> int:
    """Main entry point."""
    ch_host = os.environ.get("CH_HOST", "127.0.0.1")
    ch_port = int(os.environ.get("CH_PORT", "8123"))
    ch_user = os.environ.get("CH_USER", "default")
    ch_password = os.environ.get("CH_PASSWORD", "")

    # CH_PASSWORD is required for most operations, but can be empty for initial setup
    # The clickhouse-client will use the password if provided, or no password if empty
    # For interactive use without password, set CH_PASSWORD="" explicitly
    if ch_password:
        # Use password from environment
        os.environ["CLICKHOUSE_PASSWORD"] = ch_password

    # Get all migrations
    migrations = get_migration_files()
    if not migrations:
        print("No migration files found in", MIGRATIONS_DIR, file=sys.stderr)
        return 1

    # Get applied migrations
    applied = get_applied_migrations(ch_host, ch_port, ch_user, ch_password)

    # Find pending migrations
    pending = []
    for m in migrations:
        num = int(re.search(r"^(\d+)", m.name).group(1))
        if num not in applied:
            pending.append((num, m))

    if not pending:
        print("All migrations already applied")
        return 0

    print(f"Applying {len(pending)} pending migration(s)...")
    for num, migration_file in pending:
        print(f"Applying {migration_file.name}...")
        apply_migration(ch_host, ch_port, ch_user, migration_file)

        # Record the migration
        record_cmd = clickhouse_cmd(
            "--query",
            f"INSERT INTO ssdf.migrations_applied (migration_number, applied_at) VALUES ({num}, now())",
            ch_host=ch_host,
            ch_port=ch_port,
            ch_user=ch_user,
            ch_password=ch_password,
        )
        subprocess.run(record_cmd, check=True)
        print(f"  Applied {migration_file.name}")

    print(f"Successfully applied {len(pending)} migration(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
