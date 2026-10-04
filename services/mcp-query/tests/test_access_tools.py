import pytest

from ssdf_mcp_query.access_tools import AccessTools, _short_host, _select_pair


class _FakeStore:
    def __init__(self, entities, comm, policies):
        self._entities = entities
        self._comm = comm
        self._policies = policies

    def find_entity(self, identifier):
        return self._entities.get(identifier)

    def communicated_edges(self, a_id, b_id, since_iso):
        return self._comm

    def governed_policies(self, comm_edge_ids):
        return self._policies

    def configured_policies_for_firewalls(self, names):
        return []

    def alerts_for_pair(self, ips, since_iso):
        self.alerts_ips = ips
        return getattr(self, "_alerts", [])

    def find_entities(self, identifier):
        ent = self._entities.get(identifier)
        return [ent] if ent else []

    def communicated_edges_multi(self, a_ids, b_ids, since_iso):
        # legacy fixtures omit src_id/dst_id; stamp the top candidate of each side
        # so _select_pair maps them onto the (client, server) pair under test.
        # An edge that already carries src_id/dst_id keeps its own (explicit override).
        return [{"src_id": a_ids[0], "dst_id": b_ids[0], **edge} for edge in self._comm]


class _FakeTopo:
    def __init__(self, firewalls, path):
        self._firewalls = firewalls
        self._path = path

    def enforcement_points(self, src, dst):
        return {"firewalls": self._firewalls, "rules": [], "zones": []}

    def find_path(self, src, dst, layer="any"):
        return self._path


def _client_server():
    # keyed by the identifier strings explain_access() looks up
    return {
        "10.64.0.5": {"entity_id": "C", "name": "10.64.0.5", "identity_basis": "ip_only"},
        "8.8.8.8": {"entity_id": "S", "name": "8.8.8.8", "identity_basis": "ip_only"},
    }


def test_not_found_when_endpoint_unresolved():
    store = _FakeStore({}, [], [])
    topo = _FakeTopo([], {"found": False})
    out = AccessTools(store, topo).explain_access("nope", "8.8.8.8")
    assert out["error"] == "not_found"


def test_observed_flow_with_controls_and_coverage():
    ents = _client_server()
    comm = [
        {
            "edge_id": "E1",
            "attrs": {
                "sessions": "42",
                "bytes": "1000",
                "ports": "443",
                "providers": "juniper",
                "transports": "tcp",
            },
        }
    ]
    policies = [
        {
            "policy": {
                "name": "trust-to-untrust",
                "identifiers": {"provider": "juniper", "rule": "trust-to-untrust"},
                "source": "observed",
            },
            "edge_attrs": {"rule": "trust-to-untrust", "provider": "juniper"},
        }
    ]
    store = _FakeStore(ents, comm, policies)
    topo = _FakeTopo(["vSRX-test10"], {"found": True, "hops": 3, "path_nodes": ["C", "X", "S"]})
    out = AccessTools(store, topo).explain_access("10.64.0.5", "8.8.8.8")
    assert out["observed_flows"]["sessions"] == 42
    assert out["observed_flows"]["providers"] == ["juniper"]
    assert out["controls"][0]["rule"] == "trust-to-untrust"
    assert out["controls"][0]["source"] == "observed"
    assert out["controls"][0]["firewall"] == "vSRX-test10"
    assert out["controls"][0]["firewall_basis"] == "topology"
    assert out["coverage"] == {"observed": True, "configured": 0}
    assert out["topology_path"]["found"] is True


def test_observed_flow_without_resolved_rule_is_a_finding():
    ents = _client_server()
    comm = [
        {
            "edge_id": "E1",
            "attrs": {
                "sessions": "5",
                "bytes": "10",
                "ports": "",
                "providers": "paloalto",
                "transports": "tcp",
            },
        }
    ]
    store = _FakeStore(ents, comm, [])  # no governed_by policies
    topo = _FakeTopo([], {"found": False})
    out = AccessTools(store, topo).explain_access("10.64.0.5", "8.8.8.8")
    assert out["controls"] == []
    assert out["observed_flows"]["sessions"] == 5
    assert out["coverage"]["observed"] is True


def test_firewall_omitted_when_topology_ambiguous():
    ents = _client_server()
    comm = [
        {
            "edge_id": "E1",
            "attrs": {
                "sessions": "1",
                "bytes": "1",
                "ports": "443",
                "providers": "juniper",
                "transports": "tcp",
            },
        }
    ]
    policies = [
        {
            "policy": {
                "name": "r",
                "identifiers": {"provider": "juniper", "rule": "r"},
                "source": "observed",
            },
            "edge_attrs": {"rule": "r", "provider": "juniper"},
        }
    ]
    store = _FakeStore(ents, comm, policies)
    topo = _FakeTopo(["fw1", "fw2"], {"found": True, "hops": 4})  # two firewalls -> ambiguous
    out = AccessTools(store, topo).explain_access("10.64.0.5", "8.8.8.8")
    assert out["controls"][0]["firewall"] is None
    assert out["firewalls"] == ["fw1", "fw2"]


class _StoreWithConfigured:
    """Minimal EntityStore double exercising the configured path."""

    def __init__(self, configured):
        self._configured = configured

    def find_entity(self, ident):
        return {"entity_id": ident, "name": ident, "identity_basis": "mac"}

    def communicated_edges(self, a, b, since):
        return []

    def governed_policies(self, ids):
        return []

    def configured_policies_for_firewalls(self, names):
        return self._configured

    def alerts_for_pair(self, ips, since_iso):
        return []

    def find_entities(self, ident):
        return [self.find_entity(ident)]

    def communicated_edges_multi(self, a_ids, b_ids, since_iso):
        return []


class _TopoOneFw:
    def enforcement_points(self, src, dst):
        return {"firewalls": ["panosvm"]}

    def find_path(self, src, dst):
        return {"path": []}


def test_explain_access_lists_configured_controls_and_counts():
    from ssdf_mcp_query.access_tools import AccessTools

    configured = [
        {
            "firewall": "panosvm",
            "policy": {
                "name": "allow-web",
                "attrs": {
                    "action": "allow",
                    "from_zone": "trust",
                    "to_zone": "untrust",
                    "position": "0",
                    "enabled": "true",
                },
            },
        }
    ]
    access = AccessTools(_StoreWithConfigured(configured), _TopoOneFw())
    out = access.explain_access("10.64.0.1", "10.64.0.2")
    assert out["coverage"]["configured"] == 1
    assert out["configured_basis"] == "topology"
    ctrl = out["configured_controls"][0]
    assert ctrl["firewall"] == "panosvm" and ctrl["rule"] == "allow-web"
    assert ctrl["action"] == "allow" and ctrl["enabled"] is True
    assert ctrl["source"] == "configured"


def test_explain_access_no_path_firewall_sets_basis():
    from ssdf_mcp_query.access_tools import AccessTools

    class _TopoNoFw:
        def enforcement_points(self, src, dst):
            return {"firewalls": []}

        def find_path(self, src, dst):
            return {"path": []}

    access = AccessTools(_StoreWithConfigured([]), _TopoNoFw())
    out = access.explain_access("10.64.0.1", "10.64.0.2")
    assert out["coverage"]["configured"] == 0
    assert out["configured_basis"] == "no_path_firewall"
    assert out["configured_controls"] == []


def test_explain_access_unmatched_firewall_basis():
    from ssdf_mcp_query.access_tools import AccessTools

    # topology names a firewall, but no configured Policy entities match it
    access = AccessTools(_StoreWithConfigured([]), _TopoOneFw())
    out = access.explain_access("10.64.0.1", "10.64.0.2")
    assert out["coverage"]["configured"] == 0
    assert out["configured_basis"] == "firewall_name_unmatched"


def test_explain_access_provenance_primary_attributes_logging_firewall():
    ents = _client_server()
    comm = [
        {
            "edge_id": "E1",
            "attrs": {
                "sessions": "1",
                "bytes": "10",
                "ports": "443",
                "providers": "juniper",
                "transports": "tcp",
                "observer_hosts": "vSRX-test10",
            },
        }
    ]

    class _StoreProv(_FakeStore):
        def configured_policies_for_firewalls(self, names):
            assert names == ["vSRX-test10"]
            return [
                {
                    "firewall": "vSRX-test10",
                    "policy": {"name": "baseline-permit(global)", "attrs": {"enabled": "true"}},
                }
            ]

    class _TopoBoom(_FakeTopo):
        def enforcement_points(self, src, dst):
            raise AssertionError("enforcement_points must not be called when provenance present")

    store = _StoreProv(ents, comm, [])
    out = AccessTools(store, _TopoBoom(["fwX"], {"found": True})).explain_access(
        "10.64.0.5", "8.8.8.8"
    )
    assert out["firewall_basis"] == "provenance"
    assert out["firewalls"] == ["vSRX-test10"]
    assert out["coverage"]["configured"] == 1


def test_explain_access_falls_back_to_topology_when_no_provenance():
    ents = _client_server()
    comm = [
        {
            "edge_id": "E1",
            "attrs": {
                "sessions": "1",
                "bytes": "10",
                "ports": "443",
                "providers": "juniper",
                "transports": "tcp",
                "observer_hosts": "",
            },
        }
    ]
    store = _FakeStore(ents, comm, [])
    topo = _FakeTopo(["vSRX-test10"], {"found": True, "hops": 3})
    out = AccessTools(store, topo).explain_access("10.64.0.5", "8.8.8.8")
    assert out["firewall_basis"] == "topology"
    assert out["firewalls"] == ["vSRX-test10"]


def test_explain_access_no_provenance_no_topology_is_no_path_firewall():
    ents = _client_server()
    comm = [
        {
            "edge_id": "E1",
            "attrs": {
                "sessions": "1",
                "bytes": "10",
                "ports": "443",
                "providers": "juniper",
                "transports": "tcp",
                "observer_hosts": "",
            },
        }
    ]
    store = _FakeStore(ents, comm, [])
    out = AccessTools(store, _FakeTopo([], {"found": False})).explain_access("10.64.0.5", "8.8.8.8")
    assert out["firewall_basis"] == "no_path_firewall"
    assert out["coverage"]["configured"] == 0


def test_explain_access_provenance_preserves_mixed_case_short_name():
    ents = _client_server()
    comm = [
        {
            "edge_id": "E1",
            "attrs": {
                "sessions": "1",
                "bytes": "10",
                "ports": "443",
                "providers": "juniper",
                "transports": "tcp",
                "observer_hosts": "vSRX-test10",
            },
        }
    ]

    class _StoreProv(_FakeStore):
        def configured_policies_for_firewalls(self, names):
            assert names == ["vSRX-test10"]
            return [
                {
                    "firewall": "vSRX-test10",
                    "policy": {"name": "baseline-permit(global)", "attrs": {"enabled": "true"}},
                }
            ]

    store = _StoreProv(ents, comm, [])
    out = AccessTools(store, _FakeTopo(["fwX"], {"found": True})).explain_access(
        "10.64.0.5", "8.8.8.8"
    )
    assert out["firewall_basis"] == "provenance"
    assert out["firewalls"] == ["vSRX-test10"]
    assert out["coverage"]["configured"] == 1


def test_explain_access_provenance_normalizes_panos_fqdn():
    ents = _client_server()
    comm = [
        {
            "edge_id": "E1",
            "attrs": {
                "sessions": "1",
                "bytes": "10",
                "ports": "443",
                "providers": "paloalto",
                "transports": "tcp",
                "observer_hosts": "panosvm.example.com",
            },
        }
    ]

    class _StoreProv(_FakeStore):
        def configured_policies_for_firewalls(self, names):
            assert names == ["panosvm"]
            return [
                {
                    "firewall": "panosvm",
                    "policy": {"name": "transit-permit", "attrs": {"enabled": "true"}},
                }
            ]

    class _TopoBoom(_FakeTopo):
        def enforcement_points(self, src, dst):
            raise AssertionError("enforcement_points must not be called when provenance present")

    store = _StoreProv(ents, comm, [])
    out = AccessTools(store, _TopoBoom(["fwX"], {"found": True})).explain_access(
        "10.64.0.5", "8.8.8.8"
    )
    assert out["firewall_basis"] == "provenance"
    assert out["firewalls"] == ["panosvm"]
    assert out["coverage"]["configured"] == 1


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("panosvm.example.com", "panosvm"),
        ("vSRX-test10", "vSRX-test10"),
        ("198.51.100.1", "198.51.100.1"),
        ("fe80::1", "fe80::1"),
        ("PANOSVM.example.com", "PANOSVM"),
        ("panosvm.", "panosvm"),
    ],
)
def test_short_host(raw, expected):
    assert _short_host(raw) == expected


def test_detections_populated_from_unifi_alerts():
    ents = _client_server()
    comm = [
        {
            "edge_id": "E1",
            "attrs": {
                "sessions": "3",
                "bytes": "100",
                "ports": "443",
                "providers": "unifi",
                "transports": "tcp",
            },
        }
    ]
    store = _FakeStore(ents, comm, [])
    store._alerts = [
        {
            "timestamp": "2026-06-13 12:00:00.000",
            "source_ip": "10.64.0.5",
            "destination_ip": "8.8.8.8",
            "signature": "ET POLICY Suspicious TLS",
            "signature_id": "2027865",
            "category": "Potentially Bad Traffic",
            "severity": "2",
        }
    ]
    topo = _FakeTopo([], {"found": False})
    out = AccessTools(store, topo).explain_access("10.64.0.5", "8.8.8.8")
    assert len(out["detections"]) == 1
    det = out["detections"][0]
    assert det["signature"] == {
        "value": "ET POLICY Suspicious TLS",
        "truncated": False,
        "untrusted": True,
    }
    assert det["signature_id"] == "2027865"
    assert det["category"] == {
        "value": "Potentially Bad Traffic",
        "truncated": False,
        "untrusted": True,
    }
    assert det["severity"] == "2"


def test_detections_empty_when_no_alerts():
    ents = _client_server()
    comm = [
        {
            "edge_id": "E1",
            "attrs": {
                "sessions": "1",
                "bytes": "1",
                "ports": "443",
                "providers": "unifi",
                "transports": "tcp",
            },
        }
    ]
    store = _FakeStore(ents, comm, [])  # no _alerts attribute -> []
    topo = _FakeTopo([], {"found": False})
    out = AccessTools(store, topo).explain_access("10.64.0.5", "8.8.8.8")
    assert out["detections"] == []


def test_detections_candidate_ips_include_entity_identifiers():
    # Entities with extra IPv4 identifiers — expansion must add them to alert_ips.
    # A non-IPv4 identifier (MAC) must be excluded (not a valid IPv4Address).
    ents = {
        "10.64.0.5": {
            "entity_id": "C",
            "name": "10.64.0.5",
            "identity_basis": "mac",
            "identifiers": {
                "ip": "10.64.0.5",
                "ip2": "10.64.1.50",  # extra IPv4 — must appear in alert_ips
                "mac": "aa:bb:cc:dd:ee:ff",  # non-IPv4 — must NOT appear
            },
        },
        "8.8.8.8": {
            "entity_id": "S",
            "name": "8.8.8.8",
            "identity_basis": "ip_only",
            "identifiers": {"ip": "8.8.8.8"},
        },
    }
    comm = [
        {
            "edge_id": "E1",
            "attrs": {
                "sessions": "1",
                "bytes": "1",
                "ports": "443",
                "providers": "unifi",
                "transports": "tcp",
            },
        }
    ]
    store = _FakeStore(ents, comm, [])
    topo = _FakeTopo([], {"found": False})
    AccessTools(store, topo).explain_access("10.64.0.5", "8.8.8.8")

    recorded = store.alerts_ips
    # (a) extra identifier IP included
    assert "10.64.1.50" in recorded
    # (b) lookup args included
    assert "10.64.0.5" in recorded
    assert "8.8.8.8" in recorded
    # (c) MAC excluded
    assert "aa:bb:cc:dd:ee:ff" not in recorded
    # (d) result is sorted
    assert recorded == sorted(recorded)


def test_select_pair_most_sessions_wins():
    edges = [
        {
            "src_id": "C",
            "dst_id": "Sa",
            "last_seen": "2026-06-15 10:00:00",
            "attrs": {"sessions": "2"},
        },
        {
            "src_id": "C",
            "dst_id": "Sb",
            "last_seen": "2026-06-15 09:00:00",
            "attrs": {"sessions": "9"},
        },
    ]
    client_id, server_id, picked = _select_pair(edges, {"C"}, {"Sa", "Sb"})
    assert (client_id, server_id) == ("C", "Sb")
    assert [e["dst_id"] for e in picked] == ["Sb"]


def test_select_pair_provenance_beats_more_sessions():
    # the live M6a-twin case: a stale un-stamped pair has MORE sessions, but the
    # correctly-stamped (observer_hosts) pair must win so SRX provenance surfaces.
    edges = [
        {
            "src_id": "C",
            "dst_id": "Sa",
            "last_seen": "2026-06-15 10:00:00",
            "attrs": {"sessions": "1812", "observer_hosts": ""},
        },
        {
            "src_id": "C",
            "dst_id": "Sb",
            "last_seen": "2026-06-15 12:00:00",
            "attrs": {"sessions": "352", "observer_hosts": "vSRX-Production"},
        },
    ]
    client_id, server_id, picked = _select_pair(edges, {"C"}, {"Sa", "Sb"})
    assert (client_id, server_id) == ("C", "Sb")
    assert [e["dst_id"] for e in picked] == ["Sb"]


def test_select_pair_last_seen_breaks_session_tie():
    edges = [
        {
            "src_id": "C",
            "dst_id": "Sa",
            "last_seen": "2026-06-15 10:00:00",
            "attrs": {"sessions": "5"},
        },
        {
            "src_id": "C",
            "dst_id": "Sb",
            "last_seen": "2026-06-15 11:00:00",
            "attrs": {"sessions": "5"},
        },
    ]
    client_id, server_id, _ = _select_pair(edges, {"C"}, {"Sa", "Sb"})
    assert (client_id, server_id) == ("C", "Sb")


def test_select_pair_maps_reversed_direction():
    # edge stored server->client must still resolve to (client, server)
    edges = [{"src_id": "S", "dst_id": "C", "last_seen": "", "attrs": {"sessions": "3"}}]
    client_id, server_id, _ = _select_pair(edges, {"C"}, {"S"})
    assert (client_id, server_id) == ("C", "S")


def test_select_pair_none_when_no_edges():
    assert _select_pair([], {"C"}, {"S"}) is None


def test_select_pair_skips_edges_with_both_ends_in_one_set():
    # both ends fall in the client set -> ambiguous -> skipped -> None
    edges = [{"src_id": "C1", "dst_id": "C2", "last_seen": "", "attrs": {"sessions": "3"}}]
    assert _select_pair(edges, {"C1", "C2"}, {"S"}) is None


def test_select_pair_accumulates_multiple_edges_for_same_pair():
    # one forward (C->S) and one reversed (S->C) edge for the same logical pair
    # must land in the same bucket: sessions sum and both edges are returned.
    edges = [
        {
            "src_id": "C",
            "dst_id": "S",
            "last_seen": "2026-06-15 10:00:00",
            "attrs": {"sessions": "3"},
        },
        {
            "src_id": "S",
            "dst_id": "C",
            "last_seen": "2026-06-15 11:00:00",
            "attrs": {"sessions": "4"},
        },
    ]
    client_id, server_id, picked = _select_pair(edges, {"C"}, {"S"})
    assert (client_id, server_id) == ("C", "S")
    assert len(picked) == 2


class _PairStore:
    """EntityStore double returning explicit candidate twin sets + explicit edges.

    find_entities maps the literal "client"/"server" lookup strings to the two
    candidate lists; communicated_edges_multi returns the scripted edges verbatim
    (they already carry real src_id/dst_id).
    """

    def __init__(self, client_cands, server_cands, edges, configured=None):
        self._client_cands = client_cands
        self._server_cands = server_cands
        self._edges = edges
        self._configured = configured or []

    def find_entities(self, identifier):
        if identifier == "client":
            return self._client_cands
        if identifier == "server":
            return self._server_cands
        return []

    def communicated_edges_multi(self, a_ids, b_ids, since_iso):
        return self._edges

    def governed_policies(self, ids):
        return []

    def configured_policies_for_firewalls(self, names):
        return self._configured

    def alerts_for_pair(self, ips, since_iso):
        return []


def _ent(entity_id, basis="ip_only"):
    return {"entity_id": entity_id, "name": "8.8.8.8", "identity_basis": basis, "identifiers": {}}


def test_server_two_twins_picks_edge_bearing():
    client_cands = [_ent("C", basis="mac")]
    server_cands = [_ent("Sa"), _ent("Sb")]  # Sa has no edge; Sb does
    edges = [
        {
            "edge_id": "E1",
            "src_id": "C",
            "dst_id": "Sb",
            "last_seen": "2026-06-15 11:22:12",
            "attrs": {
                "sessions": "4",
                "bytes": "100",
                "ports": "53",
                "providers": "juniper",
                "observer_hosts": "vSRX-Production",
            },
        }
    ]
    out = AccessTools(
        _PairStore(client_cands, server_cands, edges), _FakeTopo(["fwX"], {"found": True})
    ).explain_access("client", "server")
    assert out["server"]["entity_id"] == "Sb"
    assert out["observed_flows"]["sessions"] == 4
    assert out["firewall_basis"] == "provenance"
    assert out["firewalls"] == ["vSRX-Production"]


def test_mac_vs_iponly_picks_edge_bearing():
    client_cands = [_ent("C", basis="mac")]
    # confidence-first order puts the MAC twin first, but the edge points to the ip_only twin
    server_cands = [_ent("Smac", basis="mac"), _ent("Sip", basis="ip_only")]
    edges = [
        {
            "edge_id": "E1",
            "src_id": "C",
            "dst_id": "Sip",
            "last_seen": "2026-06-15 11:22:12",
            "attrs": {
                "sessions": "2",
                "bytes": "10",
                "ports": "53",
                "providers": "juniper",
                "observer_hosts": "vSRX-Production",
            },
        }
    ]
    out = AccessTools(
        _PairStore(client_cands, server_cands, edges), _FakeTopo(["fwX"], {"found": True})
    ).explain_access("client", "server")
    assert out["server"]["entity_id"] == "Sip"
    assert out["firewall_basis"] == "provenance"
    assert out["firewalls"] == ["vSRX-Production"]


def test_no_edge_falls_back_confidence_first():
    client_cands = [_ent("C", basis="mac")]
    server_cands = [_ent("Sa"), _ent("Sb")]
    out = AccessTools(
        _PairStore(client_cands, server_cands, []), _FakeTopo([], {"found": False})
    ).explain_access("client", "server")
    assert out["client"]["entity_id"] == "C"
    assert out["server"]["entity_id"] == "Sa"  # candidates[0]
    assert out["observed_flows"]["sessions"] == 0
    assert out["firewall_basis"] == "no_path_firewall"
    assert out["coverage"]["observed"] is False


def test_single_twin_each_side_unchanged():
    # regression guard: one entity per side with an edge (panosvm-style) behaves as before
    client_cands = [_ent("C", basis="mac")]
    server_cands = [_ent("S")]
    edges = [
        {
            "edge_id": "E1",
            "src_id": "C",
            "dst_id": "S",
            "last_seen": "2026-06-15 11:22:12",
            "attrs": {
                "sessions": "7",
                "bytes": "100",
                "ports": "53",
                "providers": "paloalto",
                "observer_hosts": "panosvm.example.com",
            },
        }
    ]
    out = AccessTools(
        _PairStore(client_cands, server_cands, edges), _FakeTopo(["fwX"], {"found": True})
    ).explain_access("client", "server")
    assert out["server"]["entity_id"] == "S"
    assert out["observed_flows"]["sessions"] == 7
    assert out["firewall_basis"] == "provenance"
    assert out["firewalls"] == ["panosvm"]


class _StoreObservers:
    """EntityStore double for observed_by: resolves one entity, scripts observers."""

    def __init__(self, entity, observers):
        self._entity = entity
        self._observers = observers
        self.seen_ips = None

    def find_entities(self, identifier):
        return [self._entity] if self._entity else []

    def observers_for_ips(self, ips, since_iso):
        self.seen_ips = ips
        return self._observers

    def find_entity(self, identifier):
        return self._entity

    def communicated_edges(self, a, b, since):
        return []

    def communicated_edges_multi(self, a_ids, b_ids, since_iso):
        return []

    def governed_policies(self, ids):
        return []

    def configured_policies_for_firewalls(self, names):
        return []

    def alerts_for_pair(self, ips, since_iso):
        return []


def test_observed_by_normalizes_and_dedupes_firewalls():
    ent = {
        "entity_id": "A",
        "name": "ep-panos",
        "identifiers": {"ip": "203.0.113.20", "mac": "aa:bb:cc:dd:ee:ff"},
    }
    store = _StoreObservers(
        ent,
        [
            {"observer_hostname": "panosvm.example.com"},
            {"observer_hostname": "panosvm.example.com"},
            {"observer_hostname": "vSRX-Production"},
        ],
    )
    out = AccessTools(store, _FakeTopo([], {"found": False})).observed_by("203.0.113.20")
    assert out["entity"]["entity_id"] == "A"
    assert out["firewalls"] == ["panosvm", "vSRX-Production"]
    assert "203.0.113.20" in store.seen_ips
    assert "aa:bb:cc:dd:ee:ff" not in store.seen_ips


def test_observed_by_not_found():
    store = _StoreObservers(None, [])
    out = AccessTools(store, _FakeTopo([], {"found": False})).observed_by("nope")
    assert out["error"] == "not_found"


def test_observed_by_no_observers_returns_empty_list():
    ent = {"entity_id": "A", "name": "x", "identifiers": {"ip": "10.64.0.9"}}
    store = _StoreObservers(ent, [])
    out = AccessTools(store, _FakeTopo([], {"found": False})).observed_by("10.64.0.9")
    assert out["firewalls"] == []


def test_configured_policies_groups_dedupes_and_counts():
    rows = [
        {
            "firewall": "panosvm",
            "policy": {
                "entity_id": "p1",
                "name": "allow-web",
                "attrs": {
                    "action": "allow",
                    "from_zone": "trust",
                    "to_zone": "untrust",
                    "position": "0",
                    "enabled": "true",
                },
            },
        },
        {
            "firewall": "panosvm",
            "policy": {
                "entity_id": "p1",
                "name": "allow-web",
                "attrs": {
                    "action": "allow",
                    "from_zone": "trust",
                    "to_zone": "untrust",
                    "position": "0",
                    "enabled": "true",
                },
            },
        },
        {
            "firewall": "panosvm",
            "policy": {
                "entity_id": "p2",
                "name": "deny-all",
                "attrs": {
                    "action": "deny",
                    "from_zone": "any",
                    "to_zone": "any",
                    "position": "1",
                    "enabled": "false",
                },
            },
        },
    ]
    access = AccessTools(_StoreWithConfigured(rows), _TopoOneFw())
    out = access.configured_policies("panosvm")
    assert len(out["firewalls"]) == 1
    fw = out["firewalls"][0]
    assert fw["firewall"] == "panosvm"
    assert fw["count"] == 2
    names = sorted(r["rule"] for r in fw["rules"])
    assert names == ["allow-web", "deny-all"]
    web = next(r for r in fw["rules"] if r["rule"] == "allow-web")
    assert web["action"] == "allow" and web["enabled"] is True and web["source"] == "configured"
    deny = next(r for r in fw["rules"] if r["rule"] == "deny-all")
    assert deny["enabled"] is False


def test_configured_policies_accepts_list_and_unknown_firewall_is_empty():
    access = AccessTools(_StoreWithConfigured([]), _TopoOneFw())
    out = access.configured_policies(["nope"])
    assert out["firewalls"] == []
