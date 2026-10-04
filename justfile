set dotenv-load := false
set export := false

setup:
    for service in services/*; do if [ -f "$service/pyproject.toml" ]; then (cd "$service" && uv sync --all-extras --locked); fi; done
    pre-commit install

dev:
    @echo "Choose a service; for example: cd services/mcp-query && uv run python -m ssdf_mcp_query.server"

fmt:
    ruff format services scripts infra/clickhouse
    git diff --check

fmt-check:
    ruff format --check services scripts infra/clickhouse

lint:
    ruff check services

test:
    for service in services/*; do if [ -f "$service/pyproject.toml" ]; then echo "==> $service"; (cd "$service" && uv run pytest -m "not integration" -q); fi; done

migrate:
    CH_HOST="${CH_HOST:-127.0.0.1}" CH_NATIVE_PORT="${CH_NATIVE_PORT:-9000}" CH_USER="${CH_USER:-default}" CH_PASSWORD="$CH_PASSWORD" python3 scripts/run_migrations.py

demo:
    @echo "Starting SSDF single-host profile..."
    @echo ""
    @echo "To use the systemd single-host profile (ClickHouse + migrations + MCP Query):"
    @echo "  1. Copy unit files to /etc/systemd/system/"
    @echo "     sudo cp infra/clickhouse/ssdf-clickhouse.service /etc/systemd/system/"
    @echo "     sudo cp infra/clickhouse/ssdf-migrate.service /etc/systemd/system/"
    @echo "     sudo cp infra/clickhouse/ssdf-single-host.target /etc/systemd/system/"
    @echo "     sudo cp services/mcp-query/infra/ssdf-mcp-query.service /etc/systemd/system/"
    @echo "  2. Create /etc/ssdf/ch-migrate-password (root-owned, 0600) with the migration runner's CH password"
    @echo "  3. Enable and start: sudo systemctl enable ssdf-single-host.target && sudo systemctl start ssdf-single-host.target"
    @echo ""
    @echo "For more details, see infra/clickhouse/README.md"
    @echo ""
    @echo "Note: For development/testing without systemd, run migrations manually:"
    @echo "  CH_NATIVE_PORT=9000 python3 scripts/run_migrations.py"

guard: lint test

integration:
    @if [ "${CONFIRM_LAB_INTEGRATION:-}" != "yes" ]; then echo "Set CONFIRM_LAB_INTEGRATION=yes after reviewing ClickHouse/MCP targets and write behavior."; exit 2; fi
    for service in services/*; do if [ -f "$service/pyproject.toml" ]; then echo "==> $service"; (cd "$service" && uv run pytest -m integration -q); fi; done

e2e:
    @echo "No browser end-to-end suite is defined for SSDF."

security:
    trivy fs --scanners vuln,misconfig,secret --exit-code 1 .

release-check: fmt lint test security
