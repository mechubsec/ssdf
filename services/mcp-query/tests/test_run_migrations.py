"""Regression tests for scripts/run_migrations.py (MEC-1656 review findings on
ssdf#53): unsubstituted ${VAR} password placeholders must never reach
clickhouse-client, a fresh install must be able to bootstrap at all, a
migration-number collision must be refused rather than silently merged, a
client error while listing applied migrations must be fatal rather than
read as "nothing applied yet", and the password must never appear on argv."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "scripts"))

import run_migrations  # noqa: E402


def _write(tmp_path: Path, name: str, sql: str) -> Path:
    f = tmp_path / name
    f.write_text(sql)
    return f


# ---------------------------------------------------------------------------
# substitute_placeholders: fail-closed envsubst-style resolution
# ---------------------------------------------------------------------------


def test_substitute_placeholders_resolves_from_environment(monkeypatch):
    monkeypatch.setenv("TOPO_PW", "s3cret")
    out = run_migrations.substitute_placeholders(
        "CREATE USER x IDENTIFIED BY '${TOPO_PW}';", "003_topo_user.sql"
    )
    assert out == "CREATE USER x IDENTIFIED BY 's3cret';"


def test_substitute_placeholders_uses_default_when_unset(monkeypatch):
    monkeypatch.delenv("HEALTH_TTL_DAYS", raising=False)
    out = run_migrations.substitute_placeholders(
        "TTL now() + INTERVAL ${HEALTH_TTL_DAYS:-30} DAY", "014_health_metrics.sql"
    )
    assert out == "TTL now() + INTERVAL 30 DAY"


def test_substitute_placeholders_default_used_when_env_is_empty(monkeypatch):
    monkeypatch.setenv("HEALTH_TTL_DAYS", "")
    out = run_migrations.substitute_placeholders(
        "TTL now() + INTERVAL ${HEALTH_TTL_DAYS:-30} DAY", "014_health_metrics.sql"
    )
    assert out == "TTL now() + INTERVAL 30 DAY"


def test_substitute_placeholders_fails_closed_on_unset_var(monkeypatch):
    monkeypatch.delenv("TOPO_PW", raising=False)
    with pytest.raises(run_migrations.MigrationError) as exc:
        run_migrations.substitute_placeholders(
            "CREATE USER x IDENTIFIED BY '${TOPO_PW}';", "003_topo_user.sql"
        )
    assert "TOPO_PW" in str(exc.value)
    assert "003_topo_user.sql" in str(exc.value)


def test_substitute_placeholders_fails_closed_on_empty_var(monkeypatch):
    monkeypatch.setenv("TOPO_PW", "")
    with pytest.raises(run_migrations.MigrationError):
        run_migrations.substitute_placeholders(
            "CREATE USER x IDENTIFIED BY '${TOPO_PW}';", "003_topo_user.sql"
        )


def test_substitute_placeholders_error_never_contains_a_resolved_value(monkeypatch):
    # The one variable that *is* set must not leak into the error raised for
    # the other, unset one.
    monkeypatch.setenv("TOPO_PW", "s3cret-topo-value")
    monkeypatch.delenv("ENTITY_PW", raising=False)
    with pytest.raises(run_migrations.MigrationError) as exc:
        run_migrations.substitute_placeholders("BY '${TOPO_PW}'; BY '${ENTITY_PW}';", "fixture.sql")
    assert "s3cret-topo-value" not in str(exc.value)


def test_apply_migration_with_unset_password_never_invokes_client(tmp_path, monkeypatch):
    """The dynamic-test finding from the review: a migration with an
    unsubstituted placeholder must fail before anything reaches
    clickhouse-client, not after sending the literal placeholder text."""
    migration = _write(
        tmp_path,
        "003_topo_user.sql",
        "CREATE USER IF NOT EXISTS ssdf_topo IDENTIFIED BY '${TOPO_PW}';",
    )
    monkeypatch.delenv("TOPO_PW", raising=False)

    def _boom(*args, **kwargs):
        raise AssertionError("clickhouse-client must not be invoked for an unsubstituted migration")

    monkeypatch.setattr(subprocess, "run", _boom)

    with pytest.raises(run_migrations.MigrationError):
        run_migrations.apply_migration("127.0.0.1", 9000, "default", "", migration)


# ---------------------------------------------------------------------------
# get_migration_files: ordering and collision refusal
# ---------------------------------------------------------------------------


def test_get_migration_files_sorts_by_number_then_name(tmp_path, monkeypatch):
    monkeypatch.setattr(run_migrations, "MIGRATIONS_DIR", tmp_path)
    _write(tmp_path, "002_b.sql", "")
    _write(tmp_path, "001_a.sql", "")
    _write(tmp_path, "010_c.sql", "")
    _write(tmp_path, "012_backfill.sql.example", "")  # excluded: not a .sql file
    names = [f.name for f in run_migrations.get_migration_files()]
    assert names == ["001_a.sql", "002_b.sql", "010_c.sql"]


def test_get_migration_files_refuses_on_number_collision(tmp_path, monkeypatch):
    monkeypatch.setattr(run_migrations, "MIGRATIONS_DIR", tmp_path)
    _write(tmp_path, "021_object_book_hash.sql", "")
    _write(tmp_path, "021_migrations_tracking.sql", "")
    with pytest.raises(run_migrations.MigrationError) as exc:
        run_migrations.get_migration_files()
    assert "021" in str(exc.value)


# ---------------------------------------------------------------------------
# clickhouse_cmd / _run: password never touches argv
# ---------------------------------------------------------------------------


def test_clickhouse_cmd_never_contains_the_password():
    cmd = run_migrations.clickhouse_cmd(
        "--query", "SELECT 1", ch_host="127.0.0.1", ch_port=9000, ch_user="default"
    )
    assert "--password" not in cmd
    assert "hunter2" not in cmd


def test_run_passes_password_via_env_not_argv(monkeypatch):
    captured = {}

    def _fake_run(cmd, env=None, text=None, check=None, **kwargs):
        captured["cmd"] = cmd
        captured["env"] = env
        return subprocess.CompletedProcess(cmd, 0, stdout="")

    monkeypatch.setattr(subprocess, "run", _fake_run)
    run_migrations._run("test step", ["clickhouse-client", "--query", "SELECT 1"], "hunter2")
    assert "hunter2" not in captured["cmd"]
    assert captured["env"]["CLICKHOUSE_PASSWORD"] == "hunter2"


def test_run_error_message_omits_argv_and_output(monkeypatch):
    def _fake_run(cmd, env=None, text=None, check=None, **kwargs):
        raise subprocess.CalledProcessError(
            1, cmd, output="leaked stdout with hunter2 in it", stderr="leaked stderr"
        )

    monkeypatch.setattr(subprocess, "run", _fake_run)
    with pytest.raises(run_migrations.MigrationError) as exc:
        run_migrations._run("apply 003_topo_user.sql", ["clickhouse-client"], "hunter2")
    message = str(exc.value)
    assert "hunter2" not in message
    assert "apply 003_topo_user.sql" in message
    assert "1" in message  # exit code


# ---------------------------------------------------------------------------
# get_applied_migrations: fail closed, never silently "nothing applied"
# ---------------------------------------------------------------------------


def test_get_applied_migrations_raises_on_client_error(monkeypatch):
    def _fake_run(cmd, env=None, text=None, check=None, **kwargs):
        raise subprocess.CalledProcessError(1, cmd)

    monkeypatch.setattr(subprocess, "run", _fake_run)
    with pytest.raises(run_migrations.MigrationError):
        run_migrations.get_applied_migrations("127.0.0.1", 9000, "default", "")


def test_get_applied_migrations_parses_filenames(monkeypatch):
    def _fake_run(cmd, env=None, text=None, check=None, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, stdout="001_events.sql\n002_topology.sql\n")

    monkeypatch.setattr(subprocess, "run", _fake_run)
    applied = run_migrations.get_applied_migrations("127.0.0.1", 9000, "default", "")
    assert applied == {"001_events.sql", "002_topology.sql"}


# ---------------------------------------------------------------------------
# ensure_tracking_table: keyed on filename, self-bootstrapping
# ---------------------------------------------------------------------------


def test_ensure_tracking_table_keys_on_migration_file(monkeypatch):
    captured = {}

    def _fake_run(cmd, env=None, text=None, check=None, **kwargs):
        captured["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(subprocess, "run", _fake_run)
    run_migrations.ensure_tracking_table("127.0.0.1", 9000, "default", "")
    ddl = captured["cmd"][-1]
    assert "migration_file String" in ddl
    assert "migration_number" not in ddl


# ---------------------------------------------------------------------------
# mark_baseline / --baseline
# ---------------------------------------------------------------------------


def test_readme_lists_every_required_placeholder():
    """MEC-1672 re-review finding B: the systemd profile's EnvironmentFile=
    must supply every *_PW / VIEW_PSEUDONYM_KEY_* variable the migrations
    reference, and the README documents that list by name. A new migration
    that adds a placeholder with no default must fail this test rather than
    silently breaking a fresh systemd install at the first unset variable."""
    sql_dir = Path(__file__).resolve().parents[3] / "infra" / "clickhouse"
    readme = (sql_dir / "README.md").read_text()

    required: set[str] = set()
    for sql_file in sql_dir.glob("*.sql"):
        for match in run_migrations._PLACEHOLDER_RE.finditer(sql_file.read_text()):
            if match.group(2) is None:  # no ${VAR:-default} fallback
                required.add(match.group(1))

    assert required, "expected at least one required placeholder across infra/clickhouse/*.sql"
    missing = {name for name in required if name not in readme}
    assert not missing, f"infra/clickhouse/README.md does not document: {sorted(missing)}"


def test_mark_baseline_only_records_migrations_at_or_below_baseline(tmp_path, monkeypatch):
    recorded = []

    def _fake_record(ch_host, ch_port, ch_user, ch_password, migration_file):
        recorded.append(migration_file.name)

    monkeypatch.setattr(run_migrations, "record_migration", _fake_record)
    migrations = [
        _write(tmp_path, "001_a.sql", ""),
        _write(tmp_path, "002_b.sql", ""),
        _write(tmp_path, "003_c.sql", ""),
    ]
    marked = run_migrations.mark_baseline("127.0.0.1", 9000, "default", "", migrations, baseline=2)
    assert marked == 2
    assert recorded == ["001_a.sql", "002_b.sql"]
