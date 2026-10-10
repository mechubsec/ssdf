<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/mechub-mark.svg">
    <img src="docs/assets/mechub-mark-light.svg" width="72" alt="mechub mark">
  </picture>
</p>

<h1 align="center">ssdf</h1>

<p align="center"><strong>Sovereign Security Data Fabric — minimal, AI-native, MCP-driven</strong><br>
<em>a mechub project — sovereign network-security automation</em></p>

A minimal, AI-native security data platform built from scratch to power conversational / agent-based management of security products (NGFWs, SASE, IDaaS, XDR, etc.) through MCP tools driven by multiple LLMs.

Two principles shape every design decision:

- **AI-native, not AI-bolted-on.** The data model, APIs, and tooling exist so that LLM agents can query, correlate, and act on security data via MCP. Human UIs are secondary; the MCP tool surface is the primary product.
- **Sovereign.** All data and inference stay under the operator's control (self-hosted, no mandatory SaaS). Do not introduce hard dependencies on external/cloud SIEM/XDR platforms (e.g. Wazuh, Splunk, cloud-only LLM APIs). LLM and storage backends must be swappable, with self-hosted options as first-class citizens. "Minimal" is a hard constraint — prefer the smallest thing that works over feature-complete frameworks.

## Stack

- **Ingest = Vector (VRL transforms)** — vendor syslog normalized to ECS-ish events at ingest. Vendor log formats live ONLY in `infra/vector/vector.toml`. See [Ingest sources](#ingest-sources) for the port map.
- **Storage = ClickHouse** — `ssdf.events` (events), `ssdf.entities`/`ssdf.entity_edges` (entity graph), topology observations, `ssdf.audit`. The swappable-backend seam is the Python store classes (graphstore/entitystore), not a Rust fabric.
- **Services + MCP layer = Python** (`services/*`, uv + FastMCP) — resolvers (topo, entity, policy, public-metrics, health) on systemd timers, and the MCP tool surface in two tiers, sovereign (`:30032`) and public (`:30033`), behind an nginx TLS edge.
- **Rust is permitted, not doctrine** — use it where a future component is genuinely performance-critical; nothing in SSDF is Rust today. `rust-junosmcp` remains the external reference implementation, not part of this repo.
- **No Docker.** Each component is a plain systemd unit on its own host; the reference deployment uses one container per role. Nothing in the design depends on that particular substrate.

## Benchmarks

SSDF includes two benchmark packages for evaluating LLM tool-calling accuracy:

- **NL→SQL benchmark** (`services/evals/`) — evaluates translation of natural language to ClickHouse SQL queries against SSDF's firewall log data. See `services/evals/BENCHMARK.md` for details. **This benchmark is domain-specific to SSDF's data model** and is not suitable for general SQL generation evaluation.

- **Tool-call benchmark** ([mechubbench](https://github.com/mechubsec/mechubbench)) — evaluates routing to network automation tools (config management, policy auditing) on general firewall scenarios. This is a **separate repository** and is not included in SSDF—it's for general network automation evaluation, not SSDF-specific SQL queries.

Why two separate benchmarks? Per Conway's Law, the NL→SQL benchmark belongs in SSDF (it requires SSDF's ClickHouse schema and data), while tool-call benchmarks for general network automation belong in the shared `mechubbench` repo. The two test different skills: SQL generation vs. tool routing.

## Architecture

Data flows one direction; LLM agents are read-only consumers via MCP:

```
security products ──────► Vector VRL ──────► ClickHouse ──────► MCP tools
  SRX / PAN-OS / UniFi     normalize at        events + entity      sovereign + public
  Proxmox / Junos syslog   ingest              graph + audit               ▲
                                                                           │
                     resolvers: topo · entity · policy          LLM agents (multi-LLM)
                                public-metrics · health
```

## MCP tiers

The MCP tool surface (`services/mcp-query`) runs as two separate processes behind
the nginx edge, not one server with a permission flag:

- **Sovereign (`:30032`)** — the full tool set: raw flow/log queries, arbitrary
  guarded SQL, topology and entity resolution, configured-policy and rule-history
  tools, change-impact analysis, and ingest/fabric liveness. Tokens for this tier
  must carry a `local_only` attestation, so a hosted-model credential cannot
  authenticate to it at all.
- **Public (`:30033`)** — a separate process, separate ClickHouse user/database
  (`ssdf_public`), and secure-by-default: every data class a tool can return
  (`security_log`, `firewall_config`, `topology`, `identity`, `metrics`) starts
  labeled `sovereign`, and only `topology`, `identity`, and `metrics` can be
  flipped to `shareable` by an operator-supplied classification file
  (`MCP_CLASSIFICATION_FILE`, see `services/mcp-query/infra/ssdf-mcp-public.service`).
  A tool is only registered on this tier if *every* data class it can return is
  `shareable`. With no classification file, the public tier registers **zero**
  tools. Raw log/flow queries (`query_flows`, `describe_schema`, `top_talkers`)
  and arbitrary SQL (`run_sql`) can never be shareable — `run_sql` is excluded
  outright regardless of configuration — so the public tier never exposes raw
  security-log or firewall-config data. The tools that *can* become shareable are
  entity resolution and topology adjacency (`get_entity`, `locate`, `neighbors`,
  `find_path`, `topology_snapshot`) and de-identified aggregate metrics
  (`metric_timeseries`, `top_series`, `entity_metric_timeseries`, which use
  opaque per-entity surrogates, not real IP/MAC). Tools that return any
  `firewall_config` data (e.g. `enforcement_points`) stay sovereign-only even
  then, since `firewall_config` is not configurable. A fixed set — access/audit
  tools (`explain_access`, `configured_policies`, `observed_by`, `reidentify`,
  `recent_alerts`, `rule_history`, `rule_usage`, `unused_rules`, `explain_rule`,
  `change_impact`) and liveness tools (`ingest_status`, `fabric_status`) — is
  never constructed on the public process at all, not just filtered out. See
  `services/mcp-query/src/ssdf_mcp_query/classification.py` and `server.py` for
  the authoritative tool/data-class mapping.

## Deployment

SSDF ships as a **reference deployment**, not a quick-start installer: each
component (ClickHouse, Vector, the Python services, nginx) is a separate
systemd unit on its own host, applied by the scripts and unit files in
`infra/` and `services/*/infra/`, with TLS termination per
[`infra/nginx/`](infra/nginx/). There is no single install command and no
Docker Compose path (see [CONTRIBUTING.md](CONTRIBUTING.md)). For dev-only
setup (syncing the Python projects and pre-commit hooks), see
[CONTRIBUTING.md's Setup section](CONTRIBUTING.md#setup); for ingest
onboarding per vendor, see [`onboarding/`](onboarding).

## Ingest sources

| Port | Proto | Source | Notes |
|---|---|---|---|
| 514 | UDP | SRX flow (`security log`) | high volume, individually disposable |
| 515 | UDP | PAN-OS | |
| 516 | UDP | UniFi | CEF |
| 517 | UDP | Proxmox host syslog | pve auth + admin actions via rsyslog |
| 518 | UDP | Junos system syslog | commits, rollbacks, logins — `system syslog host` |

All five are device telemetry over UDP: high volume, and losing an individual
record is tolerable.

### The MCP control-plane audit trail does not arrive here

Audit records from the `rust*mcp` servers — who asked an MCP server to change
what, which second principal approved it — do **not** come through Vector. They
are written directly into `ssdf.audit` as hash-chained rows, per
[`docs/audit-evidence-contract-v1.md`](docs/audit-evidence-contract-v1.md) and
[`docs/audit-evidence-ingestion.md`](docs/audit-evidence-ingestion.md).

That is deliberate. A syslog path was proposed and rejected: it is cheaper, but
syslog records are unchained, and the value of this trail is that tampering is
detectable. The producing side ships in
[mecmcp](https://github.com/mechubsec/mecmcp) as `mecmcp-audit`, which
writes hash-chained segments straight into `ssdf.audit` over HTTP with a durable
outbox and retry ([mecmcp#292](https://github.com/mechubsec/mecmcp/issues/292),
closed 2026-08-24).

SSDF owns the schema; mecmcp produces against it. That split is why this repo
stays Python while the vendor-control servers stay Rust — the contract is the
integration point, not a shared runtime.

`ssdf.audit` is therefore the single place to ask "who did what" — SSDF's own
MCP servers (`tier="sovereign"`) and the `rust*mcp` family alike. `ssdf.events`
is device telemetry only.

---

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/mechub-mark.svg">
    <img src="docs/assets/mechub-mark-light.svg" width="28" alt="">
  </picture><br>
  <sub><code>a mechub project</code> · deterministic decides · the model explains · a human approves<br>
  <a href="https://github.com/fastrevmd-lab">github.com/fastrevmd-lab</a></sub>
</p>
