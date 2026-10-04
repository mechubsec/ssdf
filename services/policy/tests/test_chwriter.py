import pytest

from ssdf_common.config import ConfigError, Secret
from ssdf_policy import chwriter
from ssdf_policy.chwriter import entity_rows, edge_rows, ENTITY_COLUMNS, ENTITY_EDGE_COLUMNS
from ssdf_policy.config import Config


def _config(**overrides):
    base = dict(
        ch_host="127.0.0.1",
        ch_port=8123,
        ch_user="ssdf_entity",
        ch_password=Secret("pw"),
        ch_database="ssdf",
        tenant_id="t_main",
        enabled_collectors=("panos", "junos"),
        junos_devices=("vSRX-test10",),
        panos_device="panosvm",
    )
    base.update(overrides)
    return Config(**base)


def test_writer_default_is_plain_http(monkeypatch):
    captured = {}
    monkeypatch.setattr(
        chwriter.clickhouse_connect,
        "get_client",
        lambda **kwargs: captured.update(kwargs) or object(),
    )
    chwriter.ClickHouseEntityWriter(_config())
    assert captured["host"] == "127.0.0.1"
    assert captured["port"] == 8123
    assert captured["password"] == "pw"
    assert "interface" not in captured
    assert "ca_cert" not in captured


def test_writer_rejects_plaintext_to_non_loopback_host(monkeypatch):
    monkeypatch.setattr(
        chwriter.clickhouse_connect,
        "get_client",
        lambda **kwargs: object(),
    )
    with pytest.raises(ConfigError):
        chwriter.ClickHouseEntityWriter(_config(ch_host="10.64.0.151"))


def test_writer_secure_passes_https_and_ca(monkeypatch):
    captured = {}
    monkeypatch.setattr(
        chwriter.clickhouse_connect,
        "get_client",
        lambda **kwargs: captured.update(kwargs) or object(),
    )
    chwriter.ClickHouseEntityWriter(
        _config(ch_port=8443, ch_secure=True, ch_ca_file="/etc/ssdf/ssdf-ca.crt")
    )
    assert captured["interface"] == "https"
    assert captured["port"] == 8443
    assert captured["ca_cert"] == "/etc/ssdf/ssdf-ca.crt"


def test_writer_secure_without_ca_file_omits_ca_cert(monkeypatch):
    captured = {}
    monkeypatch.setattr(
        chwriter.clickhouse_connect,
        "get_client",
        lambda **kwargs: captured.update(kwargs) or object(),
    )
    chwriter.ClickHouseEntityWriter(_config(ch_secure=True))
    assert captured["interface"] == "https"
    assert "ca_cert" not in captured


def test_entity_rows_match_m6a_column_order():
    # Must equal services/entity ENTITY_COLUMNS so inserts target the shared table layout.
    assert ENTITY_COLUMNS == [
        "entity_id",
        "tenant_id",
        "kind",
        "name",
        "identifiers",
        "source",
        "identity_basis",
        "confidence",
        "attrs",
        "first_seen",
        "last_seen",
    ]
    assert ENTITY_EDGE_COLUMNS == [
        "edge_id",
        "tenant_id",
        "src_id",
        "dst_id",
        "edge_type",
        "source",
        "confidence",
        "attrs",
        "first_seen",
        "last_seen",
    ]
    ent = {c: c for c in ENTITY_COLUMNS}
    assert entity_rows([ent]) == [[c for c in ENTITY_COLUMNS]]
    edge = {c: c for c in ENTITY_EDGE_COLUMNS}
    assert edge_rows([edge]) == [[c for c in ENTITY_EDGE_COLUMNS]]


class _FakeQueryResult:
    def __init__(self, rows):
        self.result_rows = rows


class _FakeChClient:
    def __init__(self, query_rows=()):
        self._query_rows = query_rows
        self.inserted = None
        self.insert_table = None

    def query(self, sql, parameters=None):
        return _FakeQueryResult(self._query_rows)

    def insert(self, table, rows, column_names):
        self.insert_table = table
        self.inserted = (rows, column_names)


def _policy(name="ALLOW-WEB", action="allow"):
    return {
        "entity_id": "pol1",
        "tenant_id": "t_main",
        "kind": "policy",
        "name": name,
        "attrs": {
            "provider": "juniper",
            "device_name": "vSRX-test10",
            "action": action,
            "from_zone": "trust",
            "to_zone": "untrust",
            "enabled": "true",
            "position": "0",
        },
        "last_seen": "2026-09-28T00:00:00.000Z",
    }


def _writer_with_fake_client(monkeypatch, query_rows=()):
    fake = _FakeChClient(query_rows)
    monkeypatch.setattr(chwriter.clickhouse_connect, "get_client", lambda **kwargs: fake)
    writer = chwriter.ClickHouseEntityWriter(_config())
    return writer, fake


def test_append_policy_versions_no_policies_is_noop(monkeypatch):
    writer, fake = _writer_with_fake_client(monkeypatch)
    assert writer.append_policy_versions([]) == 0
    assert fake.inserted is None


def test_append_policy_versions_inserts_new_rule(monkeypatch):
    writer, fake = _writer_with_fake_client(monkeypatch, query_rows=[])
    n = writer.append_policy_versions([_policy()])
    assert n == 1
    assert fake.insert_table == "policy_versions"
    rows, columns = fake.inserted
    assert columns == chwriter.POLICY_VERSION_COLUMNS
    assert rows[0][columns.index("rule_name")] == "ALLOW-WEB"


def test_append_policy_versions_skips_unchanged_rule(monkeypatch):
    from ssdf_policy.policy_versions import content_hash

    policy = _policy()
    # Fake `_fetch_latest_hashes` result: same content hash already on record.
    existing_hash = content_hash(policy)
    query_rows = [("juniper", "vSRX-test10", "ALLOW-WEB", existing_hash)]
    writer, fake = _writer_with_fake_client(monkeypatch, query_rows=query_rows)
    n = writer.append_policy_versions([policy])
    assert n == 0
    assert fake.inserted is None


def _collected_object_book(device="vSRX-test10", provider="juniper"):
    return {
        "provider": provider,
        "device_name": device,
        "collected_at": "2026-09-30T00:00:00.000Z",
        "object_book": {"address_books": {"global": {"addresses": {"A1": "10.1.1.0/24"}}}},
    }


def test_append_object_book_hashes_no_devices_is_noop(monkeypatch):
    writer, fake = _writer_with_fake_client(monkeypatch)
    assert writer.append_object_book_hashes([]) == 0
    assert fake.inserted is None


def test_append_object_book_hashes_inserts_new_device(monkeypatch):
    writer, fake = _writer_with_fake_client(monkeypatch, query_rows=[])
    n = writer.append_object_book_hashes([_collected_object_book()])
    assert n == 1
    assert fake.insert_table == "object_book_hash"
    rows, columns = fake.inserted
    assert columns == chwriter.OBJECT_BOOK_HASH_COLUMNS
    assert rows[0][columns.index("device_name")] == "vSRX-test10"
    assert rows[0][columns.index("tenant_id")] == "t_main"


def test_append_object_book_hashes_skips_unchanged_device(monkeypatch):
    from ssdf_policy.object_book import content_hash

    item = _collected_object_book()
    existing_hash = content_hash(item["object_book"])
    query_rows = [("juniper", "vSRX-test10", existing_hash)]
    writer, fake = _writer_with_fake_client(monkeypatch, query_rows=query_rows)
    n = writer.append_object_book_hashes([item])
    assert n == 0
    assert fake.inserted is None
