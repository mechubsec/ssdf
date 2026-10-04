"""explain_access: end-to-end flow + observed security controls for a client→server pair."""

from __future__ import annotations

import datetime as _dt
import ipaddress

from .untrusted_text import UntrustedText

DEFAULT_WINDOW_HOURS = 24


def _since(hours: int) -> str:
    return (_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(hours=hours)).isoformat(
        timespec="milliseconds"
    )


def _csv_list(value: str) -> list[str]:
    return [item for item in value.split(",") if item]


def _short_host(name: str) -> str:
    """First DNS label of a hostname, case preserved. A bare IP is returned unchanged."""
    try:
        ipaddress.ip_address(name)  # IP guard: never dot-split an address
        return name
    except ValueError:
        return name.split(".", 1)[0]


def _select_pair(
    edges: list[dict],
    client_ids: set[str],
    server_ids: set[str],
) -> tuple[str, str, list[dict]] | None:
    """Pick the (client_id, server_id) pair, preferring provenance-bearing edges.

    Groups edges onto the pair whose client end is in client_ids and server end in
    server_ids (mapping either edge direction). Selection order: a pair whose edges
    carry firewall provenance (non-empty ``observer_hosts``) wins over one without —
    M6a twin-splitting can leave a stale un-stamped twin-pair holding more accumulated
    sessions than the correctly-stamped pair, so most-sessions alone loses the
    provenance. A pair counts as provenance-bearing if ANY of its edges carries
    observer_hosts (matching the downstream observer_hosts union). Subsequent
    tiebreaks: greatest summed sessions, then greatest edge
    last_seen, then lexicographic (client_id, server_id) for determinism. Returns
    (client_id, server_id, edges_for_pair), or None when no edge qualifies — an edge is
    skipped when neither endpoint maps to a client/server pair, or when both endpoints
    fall in the same candidate set.
    """
    pairs: dict[tuple[str, str], dict] = {}
    for edge in edges:
        src, dst = edge.get("src_id"), edge.get("dst_id")
        if src in client_ids and dst in server_ids:
            key = (src, dst)
        elif dst in client_ids and src in server_ids:
            key = (dst, src)
        else:
            continue  # both ends in the same candidate set: ambiguous, skip
        bucket = pairs.setdefault(
            key, {"edges": [], "sessions": 0, "last_seen": "", "has_prov": False}
        )
        bucket["edges"].append(edge)
        bucket["sessions"] += int(edge.get("attrs", {}).get("sessions", "0") or 0)
        if edge.get("attrs", {}).get("observer_hosts", ""):
            bucket["has_prov"] = True
        last_seen = edge.get("last_seen", "")
        if last_seen > bucket["last_seen"]:
            bucket["last_seen"] = last_seen
    if not pairs:
        return None
    (client_id, server_id), bucket = max(
        pairs.items(),
        key=lambda item: (item[1]["has_prov"], item[1]["sessions"], item[1]["last_seen"], item[0]),
    )
    return client_id, server_id, bucket["edges"]


class AccessTools:
    """Stateless access-explanation tool bound to an EntityStore + M4 TopoTools."""

    def __init__(self, entity_store, topo_tools, default_window_hours: int = DEFAULT_WINDOW_HOURS):
        self._store = entity_store
        self._topo = topo_tools
        self._window = default_window_hours

    def explain_access(self, client: str, server: str, since_hours: int | None = None) -> dict:
        client_cands = self._store.find_entities(client)
        server_cands = self._store.find_entities(server)
        if not client_cands or not server_cands:
            missing = client if not client_cands else server
            return {"error": "not_found", "detail": f"no entity matches '{missing}'"}

        window = since_hours or self._window
        client_ids = [c["entity_id"] for c in client_cands]
        server_ids = [s["entity_id"] for s in server_cands]
        edges = self._store.communicated_edges_multi(client_ids, server_ids, _since(window))

        selected = _select_pair(edges, set(client_ids), set(server_ids))
        if selected is not None:
            client_id, server_id, comm_edges = selected
            client_entity = next(c for c in client_cands if c["entity_id"] == client_id)
            server_entity = next(s for s in server_cands if s["entity_id"] == server_id)
        else:
            # no candidate pair has an edge: confidence-first single pick, sessions:0
            client_entity = client_cands[0]
            server_entity = server_cands[0]
            comm_edges = []

        sessions = bytes_total = 0
        ports: set[str] = set()
        providers: set[str] = set()
        for edge in comm_edges:
            attrs = edge.get("attrs", {})
            sessions += int(attrs.get("sessions", "0") or 0)
            bytes_total += int(attrs.get("bytes", "0") or 0)
            ports.update(_csv_list(attrs.get("ports", "")))
            providers.update(_csv_list(attrs.get("providers", "")))

        # Provenance-primary firewall attribution (spec §4.4): the firewall that LOGGED
        # the flow is, by definition, on its path. Fall back to the L2-topology heuristic
        # only when no provenance is present (it cannot attribute transit firewalls).
        observer_hosts: set[str] = set()
        for edge in comm_edges:
            observer_hosts.update(_csv_list(edge.get("attrs", {}).get("observer_hosts", "")))
        if observer_hosts:
            firewalls = sorted({_short_host(h) for h in observer_hosts})
            firewall_basis = "provenance"
        else:
            firewalls = self._topo.enforcement_points(client, server).get("firewalls", [])
            firewall_basis = "topology" if firewalls else "no_path_firewall"
        attributed_fw = firewalls[0] if len(firewalls) == 1 else None

        # M6b: configured rules on the firewalls topology places on the path. We list rules
        # present on those firewalls — no match-scoring, no drift verdicts (honesty contract).
        configured_controls: list[dict] = []
        configured_basis = "topology"
        if not firewalls:
            configured_basis = "no_path_firewall"
        else:
            for item in self._store.configured_policies_for_firewalls(firewalls):
                policy = item["policy"]
                attrs = policy.get("attrs", {})
                configured_controls.append(
                    {
                        "firewall": item["firewall"],
                        "rule": policy.get("name", ""),
                        "action": attrs.get("action", ""),
                        "from_zone": attrs.get("from_zone", ""),
                        "to_zone": attrs.get("to_zone", ""),
                        "position": attrs.get("position", ""),
                        "enabled": attrs.get("enabled", "") == "true",
                        "source": "configured",
                    }
                )
            if not configured_controls:
                configured_basis = "firewall_name_unmatched"

        controls = []
        if comm_edges:
            for item in self._store.governed_policies([e["edge_id"] for e in comm_edges]):
                policy = item["policy"]
                controls.append(
                    {
                        "firewall": attributed_fw,
                        "vendor": policy["identifiers"].get("provider", ""),
                        "rule": policy.get("name", ""),
                        "source": policy.get("source", "observed"),
                        "firewall_basis": firewall_basis,
                    }
                )

        # M9: UniFi IPS detections touching either endpoint, same window. Candidate IPs
        # come from the lookup args + entity identifiers (IPv4 only — events are IPv4).
        alert_ips: set[str] = set()
        for candidate in (
            client,
            server,
            *client_entity.get("identifiers", {}).values(),
            *server_entity.get("identifiers", {}).values(),
        ):
            try:
                ipaddress.IPv4Address(candidate)
                alert_ips.add(candidate)
            except (ipaddress.AddressValueError, ValueError):
                continue
        detections = []
        for alert in self._store.alerts_for_pair(sorted(alert_ips), _since(window)):
            # signature/category are IDS detection text sourced from the traffic a
            # sensor observed, not operator config -- same untrusted boundary as
            # alerts.AlertTools.recent_alerts (MEC-568).
            detections.append(
                {
                    "timestamp": alert.get("timestamp", ""),
                    "signature": UntrustedText.from_raw(alert.get("signature", "")).to_response(),
                    "signature_id": alert.get("signature_id", ""),
                    "category": UntrustedText.from_raw(alert.get("category", "")).to_response(),
                    "severity": alert.get("severity", ""),
                    "source_ip": alert.get("source_ip", ""),
                    "destination_ip": alert.get("destination_ip", ""),
                }
            )

        return {
            "client": {
                "entity_id": client_entity["entity_id"],
                "name": client_entity.get("name", ""),
                "identity_basis": client_entity.get("identity_basis", ""),
            },
            "server": {
                "entity_id": server_entity["entity_id"],
                "name": server_entity.get("name", ""),
                "identity_basis": server_entity.get("identity_basis", ""),
            },
            "observed_flows": {
                "sessions": sessions,
                "bytes": bytes_total,
                "ports": sorted(int(p) for p in ports),
                "providers": sorted(providers),
                "window_hours": window,
            },
            "controls": controls,
            "detections": detections,
            "configured_controls": configured_controls,
            "configured_basis": configured_basis,
            "firewalls": firewalls,
            "firewall_basis": firewall_basis,
            "topology_path": self._topo.find_path(client, server),
            "coverage": {"observed": sessions > 0, "configured": len(configured_controls)},
        }

    def observed_by(self, identifier: str, since_hours: int | None = None) -> dict:
        """Firewalls that LOGGED traffic for an IP/asset (L3 provenance, multi-FW aware)."""
        cands = self._store.find_entities(identifier)
        if not cands:
            return {"error": "not_found", "detail": f"no entity matches '{identifier}'"}
        entity = cands[0]
        window = since_hours or self._window
        candidate_ips: set[str] = set()
        for value in (identifier, *entity.get("identifiers", {}).values()):
            try:
                ipaddress.ip_address(value)
                candidate_ips.add(value)
            except (ValueError, TypeError):
                continue
        rows = self._store.observers_for_ips(sorted(candidate_ips), _since(window))
        firewalls = sorted(
            {_short_host(r["observer_hostname"]) for r in rows if r.get("observer_hostname")}
        )
        return {
            "entity": {"entity_id": entity["entity_id"], "name": entity.get("name", "")},
            "firewalls": firewalls,
        }

    def configured_policies(self, firewall) -> dict:
        """Configured security rules on the named firewall(s), grouped + deduped per firewall."""
        names = [firewall] if isinstance(firewall, str) else list(firewall)
        by_fw: dict[str, dict] = {}
        for item in self._store.configured_policies_for_firewalls(names):
            policy = item["policy"]
            attrs = policy.get("attrs", {})
            bucket = by_fw.setdefault(item["firewall"], {})
            bucket[policy["entity_id"]] = {  # dedup by policy entity_id
                "rule": policy.get("name", ""),
                "action": attrs.get("action", ""),
                "from_zone": attrs.get("from_zone", ""),
                "to_zone": attrs.get("to_zone", ""),
                "position": attrs.get("position", ""),
                "enabled": attrs.get("enabled", "") == "true",
                "source": "configured",
            }
        firewalls = [
            {"firewall": name, "rules": list(rules.values()), "count": len(rules)}
            for name, rules in sorted(by_fw.items())
        ]
        return {"firewalls": firewalls}
