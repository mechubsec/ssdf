import datetime

from ssdf_policy.flow_tuples_rollup import (
    FLOW_TUPLES_COLUMNS,
    JUNOS_NAT_DEST_KEY,
    PANOS_APP_KEY,
    compute_window,
    effective_app,
    effective_destination_ip,
    run_once,
)


def test_compute_window_truncates_to_whole_days():
    now = datetime.datetime(2026, 9, 28, 14, 37, 12, tzinfo=datetime.timezone.utc)
    since, until = compute_window(now, lookback_days=3)
    assert until == datetime.datetime(2026, 9, 28, 0, 0, 0, tzinfo=datetime.timezone.utc)
    assert since == datetime.datetime(2026, 9, 25, 0, 0, 0, tzinfo=datetime.timezone.utc)


# Effective-tuple NAT handling (change-impact-scope doc §1.3): Junos applies
# static/destination NAT *before* the policy lookup, so the post-DNAT address
# is what the rulebase actually saw; PAN-OS matches on pre-NAT addresses, so
# its logged destination_ip is already the effective value.


def test_junos_destination_uses_nat_destination_when_present():
    ext = {JUNOS_NAT_DEST_KEY: "10.66.2.20"}
    assert effective_destination_ip("juniper", "203.0.113.5", ext) == "10.66.2.20"


def test_junos_destination_falls_back_when_no_nat_rewrite():
    # No DNAT configured for this flow: nat-destination-address is absent.
    assert effective_destination_ip("juniper", "10.66.2.20", {}) == "10.66.2.20"


def test_junos_destination_falls_back_on_zero_address_sentinel():
    # RT_FLOW emits "0.0.0.0" rather than omitting the field when no
    # destination NAT rule matched (see srx-ingest fixture doc).
    ext = {JUNOS_NAT_DEST_KEY: "0.0.0.0"}
    assert effective_destination_ip("juniper", "10.66.2.20", ext) == "10.66.2.20"


def test_panos_destination_is_always_pre_nat():
    # Even when the vector pipeline captured a NAT dest under a different ext
    # key (panw.panos.nat_destination_ip), PAN-OS policy matches pre-NAT, so
    # the effective destination is always the logged destination_ip.
    ext = {"panw.panos.nat_destination_ip": "198.51.100.9"}
    assert effective_destination_ip("paloalto", "10.1.1.50", ext) == "10.1.1.50"


def test_panos_app_reads_the_logged_app_id():
    ext = {PANOS_APP_KEY: "ssl"}
    assert effective_app("paloalto", ext) == "ssl"


def test_junos_app_is_not_modeled_here():
    # Junos's application match is protocol/port sets, already covered by the
    # typed transport/dst_port columns; there is no comparable field to pull.
    ext = {PANOS_APP_KEY: "ssl"}
    assert effective_app("juniper", ext) == ""


class _FakeQueryResult:
    def __init__(self, rows):
        self.result_rows = rows


class _FakeChClient:
    def __init__(self, rows):
        self._rows = rows
        self.inserted = None
        self.insert_table = None
        self.last_params = None

    def query(self, sql, parameters=None):
        self.last_params = parameters
        return _FakeQueryResult(self._rows)

    def insert(self, table, rows, column_names):
        self.insert_table = table
        self.inserted = (rows, column_names)


def test_run_once_inserts_rolled_up_rows():
    rows = [
        (
            "t_main",
            "vsrx-ci",
            "trust",
            "untrust",
            "2026-09-28",
            "10.65.1.10",
            "10.66.2.20",
            "tcp",
            443,
            "",
            "juniper",
            5,
            1500,
            "2026-09-28T11:00:00",
            "2026-09-28T11:05:00",
            ["trust-to-untrust"],
            ["success"],
        )
    ]
    client = _FakeChClient(rows)
    n = run_once(client, datetime.datetime(2026, 9, 28, 14, 0, 0, tzinfo=datetime.timezone.utc))
    assert n == 1
    assert client.insert_table == "flow_tuples_daily"
    inserted_rows, columns = client.inserted
    assert columns == FLOW_TUPLES_COLUMNS
    assert inserted_rows == [list(rows[0])]


def test_run_once_no_rows_skips_insert():
    client = _FakeChClient([])
    n = run_once(client, datetime.datetime(2026, 9, 28, 14, 0, 0, tzinfo=datetime.timezone.utc))
    assert n == 0
    assert client.inserted is None
