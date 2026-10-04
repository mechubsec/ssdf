"""Effective-tuple extraction (doc §1.3): what the policy engine actually saw,
reconstructed from one historical log row (or one aggregated candidate row --
same field shape either way).

NAT ordering is vendor-specific and is the main source of a wrong verdict if
mishandled: Junos applies static/destination NAT *before* the policy lookup
(so the effective destination is the NAT'd one) and source NAT *after* (so the
effective source is the pre-NAT one, already `source_ip` in the log). PAN-OS
matches security policy on pre-NAT IPs for both directions. Source port is
always dropped: it's ephemeral and not something a static rule can key on
without a `match_unknown` application anyway (doc §1.3).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FlowTuple:
    ingress_zone: str
    egress_zone: str
    src_ip: str | None
    dst_ip: str | None
    transport: str | None
    dst_port: int | None
    app: str | None = None  # PAN-OS post-App-ID application name, if logged


def _as_int(value) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _nonzero(value: str | None) -> str | None:
    if not value or value == "0.0.0.0":
        return None
    return value


def effective_tuple(row: dict, provider: str) -> FlowTuple:
    """Build the effective tuple the policy engine saw from one raw/aggregated
    event row. `row` keys follow the Vector-normalized `ssdf.events` shape:
    `source_ip`, `destination_ip`, `observer_ingress_zone`,
    `observer_egress_zone`, `network_transport`, `destination_port`, and an
    `ext` map for vendor-specific fields.
    """
    ext = row.get("ext") or {}
    ingress_zone = row.get("observer_ingress_zone") or ""
    egress_zone = row.get("observer_egress_zone") or ""
    transport = row.get("network_transport") or None
    dst_port = _as_int(row.get("destination_port"))
    src_ip = row.get("source_ip") or None

    if provider == "juniper":
        nat_dst = _nonzero(ext.get("nat-destination-address"))
        dst_ip = nat_dst if nat_dst is not None else (row.get("destination_ip") or None)
        app = None
    elif provider == "paloalto":
        dst_ip = row.get("destination_ip") or None
        app = ext.get("panw.panos.application") or None
    else:
        raise ValueError(f"unsupported provider: {provider!r}")

    return FlowTuple(
        ingress_zone=ingress_zone,
        egress_zone=egress_zone,
        src_ip=src_ip,
        dst_ip=dst_ip,
        transport=transport,
        dst_port=dst_port,
        app=app,
    )
