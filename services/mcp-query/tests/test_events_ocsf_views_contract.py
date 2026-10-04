"""MEC-571 rework (F1/F3/F4/F7): the OCSF event export views in
026_events_ocsf_export.sql and 027_events_ocsf_authentication.sql are
string-matched by test_events_ocsf_export_migration.py and
test_events_ocsf_authentication_migration.py, but string matching cannot
prove what a view actually returns. scripts/apply_contract_schema.py does
not apply these two files (they CREATE USER with envsubst placeholders,
which the plain-DDL contract schema step deliberately skips), so nothing
else in CI runs their SQL against a real server either.

This file applies both migrations itself, with test-only secrets, against
the same throwaway ClickHouse service container test_public_views_migration.py
uses, then seeds synthetic events and checks:

- neither view projects `ext` or `raw` (F1 -- both can carry
  attacker-influenceable or device-internal text).
- the network-activity view excludes alerts, so an IDS/IPS hit is not
  double-counted as both an alert and network activity (F3).
- the authentication view returns one row per matching event, not one row
  per category, and does not match unrelated actions on an "auth" substring
  (F4).
- ssdf_events_export can read the views but not the base table (same access
  model as 024's audit export, proven here rather than asserted).

Marked ``contract`` (needs only a throwaway ClickHouse), same as
test_public_views_migration.py.
"""

from __future__ import annotations

import os
import pathlib
import urllib.error
import urllib.request

import pytest

pytestmark = pytest.mark.contract

clickhouse_connect = pytest.importorskip("clickhouse_connect")

CLICKHOUSE_DIR = pathlib.Path(__file__).resolve().parents[3] / "infra" / "clickhouse"
NETWORK_MIGRATION = CLICKHOUSE_DIR / "026_events_ocsf_export.sql"
AUTH_MIGRATION = CLICKHOUSE_DIR / "027_events_ocsf_authentication.sql"

# Throwaway values for a throwaway container -- never used against a real deploy.
_DEFINER_PW = "contract-test-events-ocsf-definer-pw"
_EXPORT_PW = "contract-test-events-export-pw"

_TENANT = "t_contract_events_ocsf"
_SECRET_EXT_VALUE = "panw-nat-session-should-never-leak"
_SECRET_RAW_VALUE = "raw-vendor-payload-should-never-leak"


def _statements(sql: str):
    """Strip comment lines first, then split on ';' -- these migrations'
    header comments contain semicolons of their own (e.g. "enough); its
    password is ..."), which a split-then-strip order would cut mid-comment."""
    code_only = "\n".join(
        line for line in sql.splitlines() if line.strip() and not line.strip().startswith("--")
    )
    for chunk in code_only.split(";"):
        statement = chunk.strip()
        if statement:
            yield statement


def _render(path: pathlib.Path) -> str:
    rendered = path.read_text(encoding="utf-8")
    for key, value in (
        ("EVENTS_OCSF_DEFINER_PW", _DEFINER_PW),
        ("EVENTS_EXPORT_PW", _EXPORT_PW),
    ):
        rendered = rendered.replace("${%s}" % key, value)
    return rendered


def _apply(base_url: str, sql: str) -> None:
    for statement in _statements(sql):
        try:
            urllib.request.urlopen(
                urllib.request.Request(base_url, data=statement.encode("utf-8"), method="POST"),
                timeout=30,
            ).read()
        except urllib.error.HTTPError as exc:
            raise AssertionError(
                f"applying migration failed: {exc.read().decode('utf-8', 'replace')}"
            ) from exc


@pytest.fixture(scope="module")
def base_url() -> str:
    host = os.environ.get("CH_CONTRACT_HOST")
    if not host:
        pytest.skip("set CH_CONTRACT_HOST to run the SQL contract suite")
    port = int(os.environ.get("CH_CONTRACT_PORT", "8123"))
    return f"http://{host}:{port}/"


def _insert_event(base_url: str, **fields) -> None:
    columns = ", ".join(fields)
    values = ", ".join(fields.values())
    urllib.request.urlopen(
        urllib.request.Request(
            base_url,
            data=f"INSERT INTO ssdf.events ({columns}) VALUES ({values})".encode("utf-8"),
            method="POST",
        ),
        timeout=30,
    ).read()


@pytest.fixture(scope="module", autouse=True)
def applied(base_url):
    """Seed one event of each shape the F3/F4 findings turned on, then apply
    both migrations under test."""
    common = {
        "timestamp": "now()",
        "tenant_id": f"'{_TENANT}'",
        "source_ip": "'10.0.0.1'",
        "destination_ip": "'10.0.0.2'",
        "network_transport": "'tcp'",
        "rule_name": "'contract-test-rule'",
        "observer_ingress_zone": "'trust'",
        "observer_egress_zone": "'untrust'",
        "ext": f"{{'session_id':'{_SECRET_EXT_VALUE}'}}",
        "raw": f"'{_SECRET_RAW_VALUE}'",
    }

    # Authentication event: must appear exactly once in the authentication
    # view, and must NOT appear in the network-activity view (event_kind is
    # 'event' but event_category has no 'network').
    _insert_event(
        base_url,
        event_id="'contract-evt-login'",
        event_kind="'event'",
        event_category="['authentication']",
        event_action="'login'",
        event_outcome="'success'",
        event_provider="'contract-test'",
        user_name="'alice'",
        **common,
    )

    # IDS/IPS alert: event_kind = 'alert', category includes 'network'. Must
    # be excluded from the network-activity view (F3) and from the
    # authentication view.
    _insert_event(
        base_url,
        event_id="'contract-evt-ips-alert'",
        event_kind="'alert'",
        event_category="['network','intrusion_detection']",
        event_action="'ips_alert'",
        event_outcome="'unknown'",
        event_provider="'contract-test'",
        user_name="''",
        **common,
    )

    # Flow event whose action contains the substring "auth" but is not an
    # authentication event. Must NOT appear in the authentication view (F4).
    _insert_event(
        base_url,
        event_id="'contract-evt-unauthorized-app'",
        event_kind="'event'",
        event_category="['network']",
        event_action="'unauthorized_app'",
        event_outcome="'failure'",
        event_provider="'contract-test'",
        user_name="''",
        **common,
    )

    # Plain network flow close: the one row that should reach the
    # network-activity view.
    _insert_event(
        base_url,
        event_id="'contract-evt-flow-close'",
        event_kind="'event'",
        event_category="['network']",
        event_action="'flow_close'",
        event_outcome="'success'",
        event_provider="'contract-test'",
        user_name="''",
        **common,
    )

    _apply(base_url, _render(NETWORK_MIGRATION))
    _apply(base_url, _render(AUTH_MIGRATION))


@pytest.fixture(scope="module")
def admin_client(base_url, applied):
    from urllib.parse import urlparse

    parsed = urlparse(base_url)
    return clickhouse_connect.get_client(
        host=parsed.hostname, port=parsed.port, username="default", password="", database="ssdf"
    )


def test_network_view_never_projects_ext_or_raw(admin_client):
    columns = {row[0] for row in admin_client.query("DESCRIBE ssdf.events_ocsf_export").result_rows}
    assert "metadata" not in columns
    assert "raw" not in columns
    assert "ext" not in columns


def test_authentication_view_never_projects_ext_or_raw(admin_client):
    columns = {
        row[0]
        for row in admin_client.query("DESCRIBE ssdf.events_ocsf_authentication_export").result_rows
    }
    assert "metadata" not in columns
    assert "raw" not in columns
    assert "ext" not in columns


def test_network_view_excludes_alerts_and_auth_events(admin_client):
    """F3: only the plain flow event and the mislabeled-substring flow event
    are network activity -- not the login (no 'network' category) and not
    the IPS alert (event_kind = 'alert')."""
    rows = admin_client.query(
        "SELECT DISTINCT activity_name FROM ssdf.events_ocsf_export "
        f"WHERE cloud_account_id = '{_TENANT}' ORDER BY activity_name"
    ).result_rows
    assert [r[0] for r in rows] == ["flow_close", "unauthorized_app"]


def test_network_view_leaks_no_ext_or_raw_content(admin_client):
    dump = str(
        admin_client.query(
            f"SELECT * FROM ssdf.events_ocsf_export WHERE cloud_account_id = '{_TENANT}'"
        ).result_rows
    )
    assert _SECRET_EXT_VALUE not in dump
    assert _SECRET_RAW_VALUE not in dump


def test_authentication_view_matches_only_the_login_event_once(admin_client):
    """F4: no arrayJoin duplication, and the 'unauthorized_app' substring
    match must not let a non-authentication flow event through."""
    rows = admin_client.query(
        "SELECT DISTINCT activity_name FROM ssdf.events_ocsf_authentication_export "
        f"WHERE cloud_account_id = '{_TENANT}'"
    ).result_rows
    assert [r[0] for r in rows] == ["login"]


def test_authentication_view_leaks_no_ext_or_raw_content(admin_client):
    dump = str(
        admin_client.query(
            "SELECT * FROM ssdf.events_ocsf_authentication_export "
            f"WHERE cloud_account_id = '{_TENANT}'"
        ).result_rows
    )
    assert _SECRET_EXT_VALUE not in dump
    assert _SECRET_RAW_VALUE not in dump


def test_export_identity_can_read_views_but_not_the_base_table(base_url):
    from urllib.parse import urlparse

    parsed = urlparse(base_url)
    client = clickhouse_connect.get_client(
        host=parsed.hostname,
        port=parsed.port,
        username="ssdf_events_export",
        password=_EXPORT_PW,
        database="ssdf",
    )
    client.query("SELECT count() FROM ssdf.events_ocsf_export")
    client.query("SELECT count() FROM ssdf.events_ocsf_authentication_export")
    with pytest.raises(Exception):
        client.query("SELECT count() FROM ssdf.events")
