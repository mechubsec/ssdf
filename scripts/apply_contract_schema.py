#!/usr/bin/env python3
"""Create the tables the SQL contract suite needs, in a throwaway ClickHouse.

Applies ONLY the plain-DDL migrations -- between them they create every table
the mcp-query query builders read (events, graph_nodes/graph_edges, entities/
entity_edges). The rest of infra/clickhouse/ creates users, grants and views and
needs `envsubst` with real passwords, none of which the contract suite touches.

Statements are split and sent one at a time over the HTTP interface: ClickHouse
rejects multi-statement bodies there, and requiring the `clickhouse-client`
binary would mean installing it on the CI runner just for this.

This is a script rather than an inline CI heredoc so the same code runs locally
and in CI -- a schema step that only exists in a workflow file cannot be tested
before it fails there.

Usage:
    python3 scripts/apply_contract_schema.py [--host 127.0.0.1] [--port 8123]

REFUSES any host that is not loopback unless --i-know-this-is-not-the-lab is
passed. It issues DDL; pointing it at the lab ClickHouse is not a thing to do
by accident.
"""

from __future__ import annotations

import argparse
import pathlib
import sys
import urllib.error
import urllib.parse
import urllib.request

MIGRATIONS = (
    "001_events",
    "002_topology",
    "004_entities",
    "006_observer_hostname",
    "028_host_logs",
)
LOOPBACK = {"127.0.0.1", "localhost", "::1"}


def statements(sql: str):
    """Yield executable statements, dropping comment-only and empty fragments."""
    for chunk in sql.split(";"):
        lines = [
            line
            for line in chunk.splitlines()
            if line.strip() and not line.strip().startswith("--")
        ]
        statement = "\n".join(lines).strip()
        if statement:
            yield statement


def apply(host: str, port: int, repo_root: pathlib.Path) -> int:
    base = f"http://{host}:{port}/"
    applied = 0
    for name in MIGRATIONS:
        path = repo_root / "infra" / "clickhouse" / f"{name}.sql"
        if not path.is_file():
            print(f"missing migration: {path}", file=sys.stderr)
            return 2
        for statement in statements(path.read_text()):
            # The throwaway server has no ssdf_ro user; grants are access, not schema.
            if statement.upper().startswith("GRANT "):
                continue
            # POST with the statement as the body: over HTTP, GET implies
            # readonly mode and ClickHouse refuses DDL sent that way.
            try:
                urllib.request.urlopen(
                    urllib.request.Request(base, data=statement.encode("utf-8"), method="POST"),
                    timeout=30,
                ).read()
            except urllib.error.HTTPError as exc:
                print(f"{name}: {exc.read().decode('utf-8', 'replace')}", file=sys.stderr)
                return 1
            applied += 1
        print(f"applied {name}")
    print(f"{applied} statements applied to {host}:{port}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8123)
    parser.add_argument(
        "--i-know-this-is-not-the-lab",
        action="store_true",
        help="permit a non-loopback host (this script issues DDL)",
    )
    args = parser.parse_args()

    if args.host not in LOOPBACK and not args.i_know_this_is_not_the_lab:
        print(
            f"refusing to apply DDL to non-loopback host {args.host!r}; "
            "pass --i-know-this-is-not-the-lab if that is truly intended",
            file=sys.stderr,
        )
        return 2

    return apply(args.host, args.port, pathlib.Path(__file__).resolve().parents[1])


if __name__ == "__main__":
    sys.exit(main())
