# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project is

**SSDF — Sovereign Security Data Fabric.** A minimal, AI-native security data platform
built from scratch to power **conversational / agent-based management of security
products** (NGFWs, SASE, IDaaS, XDR, etc.) through **MCP tools driven by multiple LLMs**.

Two principles shape every design decision:

- **AI-native, not AI-bolted-on.** The data model, APIs, and tooling exist so that LLM
  agents can query, correlate, and act on security data via MCP. Human UIs are secondary;
  the MCP tool surface is the primary product.
- **Sovereign.** All data and inference stay under the operator's control (self-hosted,
  no mandatory SaaS). Do **not** introduce hard dependencies on external/cloud SIEM/XDR
  platforms (e.g. Wazuh, Splunk, cloud-only LLM APIs). LLM and storage backends must be
  swappable, with self-hosted options as first-class citizens. "Minimal" is a hard
  constraint — prefer the smallest thing that works over feature-complete frameworks.

## Stack (as built)

- **Ingest = Vector (VRL transforms)** on LXC ct102 — vendor syslog (SRX UDP/514,
  PAN-OS UDP/515) normalized to ECS-ish events at ingest. Vendor log formats live ONLY
  in `infra/vector/vector.toml`.
- **Storage = ClickHouse** on LXC ct104 — `ssdf.events` (events), `ssdf.entities`/
  `ssdf.entity_edges` (entity graph), topology observations, `ssdf.audit`. The
  swappable-backend seam is the Python store classes (graphstore/entitystore), not a
  Rust fabric.
- **Services + MCP layer = Python** (`services/*`, uv + FastMCP) — resolvers
  (topo/entity/policy on ct109 systemd timers) and the MCP tool surface
  (sovereign ct106 :30032, public ct113 :30033) behind an nginx TLS edge.
- **Rust is permitted, not doctrine** — use it where a future component is genuinely
  performance-critical; nothing in SSDF is Rust today. `rust-junosmcp` remains the
  external reference implementation, not part of this repo.
- Everything runs on Proxmox LXCs (no Docker) on pve2.example.com (see "Deployment coordinates" below; the stack moved off pve3 on 2026-08-12).

## Architecture (as built)

Data flows one direction; LLM agents are read-only consumers via MCP:

```
security products ──► Vector VRL (ct102) ──► ClickHouse (ct104) ──► MCP tools (ct106/ct113)
  SRX / PAN-OS syslog    normalize at ingest     events + entity        ▲
                                                 graph + audit          │
                          resolvers (ct109): topo/entity/policy   LLM agents (multi-LLM)
```

- **Ingest (Vector):** the only place vendor-specific log formats live; normalize at
  ingest into the common event schema.
- **Data fabric (ClickHouse + Python resolvers):** the system of record — events plus
  derived entity/topology/policy graph; correlation happens in the resolvers.
- **MCP tool layer (Python/FastMCP):** exposes the fabric as MCP tools. This is the
  contract LLM agents bind to. Treat tool definitions as the public API.
- **Agent/LLM layer:** multiple LLMs behind MCP; no single model provider may be
  load-bearing. **SSDF is read-only**: it stores, queries, and correlates — it never
  applies configuration to security products in its own data path (onboarding configs
  are applied by the operator via external vendor MCPs, e.g. rust-junosmcp/panos-mcp).

### Cross-cutting rules

- **Normalize at ingest, never downstream.** A single common schema is the contract every
  other layer depends on. Schema changes ripple everywhere — treat them as breaking and
  version them.
- **The MCP tool surface is an API.** Adding/renaming/removing a tool changes what every
  agent and LLM can do. Design tools to be safe for autonomous invocation (clear scope,
  explicit destructive-action gating) given they manage live security infrastructure.
- **Provider-agnostic by construction.** Anything that assumes one specific LLM, one storage
  engine, or one SIEM violates the sovereignty principle. Put such choices behind interfaces.

## Deployment coordinates (current — renumbered + migrated 2026-08-12)

**The SSDF stack was renumbered into the 700 band and migrated from pve3 to pve2.**
The old `ct1xx` VMIDs no longer exist in the cluster. Sections below were written
against the old numbering and still use the `ct1xx` labels as *names for the same
guests* — this table is the authority for anything you actually run.

| Role | Current | Old label | Host | IP |
|---|---|---|---|---|
| Vector ingest | **700** `ssdf-log-ingest` | ct102 | pve2 | 198.51.100.150 |
| ClickHouse | **701** `ssdf-event-store` | ct104 | pve2 | 198.51.100.151 |
| Sovereign MCP | **702** `ssdf-sovereign-mcp` | ct106 | pve2 | 198.51.100.152 |
| Public MCP | **703** `ssdf-public-mcp` | ct113 | pve2 | 198.51.100.154 |
| Resolvers (topo/entity/policy/public-metrics/health) | **704** `ssdf-topo` | ct109 | pve2 | 198.51.100.153 |
| Traffic gen (SRX) | **710** `ssdf-traffic-gen-srx` | ct198 | pve2 | 192.0.2.20 |
| Traffic gen (PAN-OS) | **711** `ssdf-traffic-gen-panos` | ct199 | pve2 | 203.0.113.20 |

Resolve a guest's node before node-local commands — guests migrate:
`pvesh get /cluster/resources --type vm`. Reach them as
`ssh root@pve2.example.com "pct exec <vmid> -- ..."`.

**Vendor MCP endpoints (renamed to prod identities + TLS, 2026-08-15).** The
collectors on 704 dial these; they are Let's Encrypt certs on LAN DNS, so no CA
file is needed, but the `--allowed-host` gate means you MUST dial the hostname,
not the IP:

- Junos: `https://prod-junosmcp.example.com:30031/mcp` (LXC 950) — tool
  `execute_junos_command(router_name, command)`
- PAN-OS: `https://prod-panosmcp.example.com:30031/mcp` (LXC 960) — tools
  `execute_panos_op(device, command)` + `get_panos_config(device)`. These were
  renamed from `execute_pan_op(host, cmd)` / `get_pan_config(host)`, and
  `get_panos_config` now nests its payload as `{"output": {"content": "<xml>"}}`.

SSDF's collector tokens are named `ssdf-collector` on both servers, scoped to the
read-only tools above.

## Commands

Device naming: see docs/naming-standard.md (fleet role-renamed 2026-07-06).

### Repo-wide checks (established 2026-08-26)

- **One version across the monorepo.** The root `VERSION` file is the published
  number; all eight `services/*/pyproject.toml` declare the same one, and each
  `uv.lock` records it for its local package. Bumping means: edit `VERSION`, bump
  the eight pyprojects, then `uv lock` in each — a bumped pyproject with a stale
  lock breaks `just setup` (`uv sync --locked`) rather than failing a test.
  `services/common/tests/test_version_consistency.py` enforces both halves; the
  repo shipped v0.1.0 through v0.1.2 with every service still reading `0.1.0`
  because nothing connected them.

- **CI runs everything.** `.github/workflows/ci.yml` = one `ruff` job (check +
  format, pinned 0.12.4 to match `.pre-commit-config.yaml`) + a matrix leg per
  service. It replaced a workflow that covered `mcp-query` alone, leaving 312 of
  the repo's tests unrun. There are no `paths:` filters on purpose: a
  path-filtered workflow does not fire on a branch-creation push, which is how
  the old one never ran at all.
- **`ruff.toml` has no per-file-ignores.** The 29-entry adoption baseline hid 40
  real violations and was cleared, not carried. The single intentional exception
  is a local `# noqa: F401` on `server.py`'s `Auditor` re-export, which is a test
  patch seam — a fact that has to live on that line, because an "unused import"
  cleanup will otherwise delete it and break every server-build test.
- **Two drift guards exist; do not delete them when they fail.** A failure means
  the thing they protect actually drifted:
  - `services/evals/tests/test_registry_drift.py` — the eval corpus tool
    registry vs `mcp-query`'s `TOOL_DATA_CLASSES`. Four served tools were once
    absent from the corpus and therefore untestable.
  - `services/common/tests/test_ci_matrix.py` — the CI matrix vs the services
    that exist, so a new service cannot ship without CI.
- **Locally:** `just lint`, `just test`, or per service
  `cd services/<name> && uv run pytest -m "not integration" -q`.

### M1 (SRX → Vector → ClickHouse)
- Run Vector unit tests: `vector test infra/vector/vector.toml`
- Validate Vector config: `CH_HOST=127.0.0.1 vector validate --no-environment infra/vector/vector.toml`
- Apply ClickHouse schema: `CH_HOST=<ip> ./scripts/apply_clickhouse_schema.sh`
- Query events: `clickhouse-client --host <ch-host> --query "SELECT ... FROM ssdf.events ..."`
- Infra runs on Proxmox LXC (no Docker): ClickHouse=701 (ct104), Vector=700 (ct102) on pve2.example.com.
- SRX onboarding applied via rust-junosmcp using onboarding/srx/stream-config.set.

### M2 (MCP query layer — ssdf-mcp-query)
- Unit tests: `cd services/mcp-query && uv run pytest -m "not integration"`
- Integration tests (live CH): `CH_HOST=<ip> CH_USER=ssdf_ro CH_PASSWORD=<pw> uv run pytest -m integration`
- Run locally: `uv run python -m ssdf_mcp_query.server`
- Deployed: streamable-HTTP MCP on its own Proxmox LXC (ct106, no Docker), bearer-token auth,
  reading ClickHouse ct104 as the read-only `ssdf_ro` user. As-built coords in gitignored
  `services/mcp-query/infra/ENV.local`.
- Add to an agent via `.mcp.json`: `{"type":"http","url":"http://<ip>:30032/mcp",
  "headers":{"Authorization":"Bearer <token>"}}`.

### M3 (PAN-OS ingest — Vector VRL/CSV → ClickHouse)
- Run Vector unit tests (on ct102 where Vector is installed, not dev host): `ssh root@pve2.example.com "pct exec 700 -- bash -c 'cd /etc/vector && vector test vector.toml'"` or push the toml and run `vector test infra/vector/vector.toml` remotely.
- Validate config locally (syntax only, no live sinks): `CH_HOST=127.0.0.1 vector validate --no-environment infra/vector/vector.toml`
- PAN-OS source: Vector ct102 listens UDP **port 515** (SRX uses 514; PAN-OS is separate source to avoid collision).
- Onboarding artifact: `onboarding/panos/log-forwarding.set` — apply to host `panosvm` (Proxmox guest 908 `3rdparty-fw`) via panos-mcp. Apply through the server's approved change-set lifecycle — `get_candidate_fingerprint` → `create_panos_change_set` → `approve_panos_change_set` → `apply_panos_change_set` → `diff_panos_candidate` → `validate_panos_candidate` → `commit_panos_candidate`. Do NOT reach for `stage_panos_config`: it is the legacy direct-write path and bypasses independent approval. The old `pan_config_diff` / `load_and_commit_pan_config` names were retired in the 2026-08-15 prod rename. SSDF never applies device config in its own data path.
- Sample query: `clickhouse-client --host <ch-host> --query "SELECT event_action, count() FROM ssdf.events WHERE event_provider='paloalto' GROUP BY event_action"`
- PAN-OS version pinned: **12.1.5**. Field positions in the `panos_ecs` VRL transform are tied to the PAN-OS 12.1 default CSV syslog format — re-validate the transform on any major PAN-OS upgrade before relying on parsed fields.

### M4 (topology graph — services/topo + topology MCP tools)
- Unit tests: `cd services/topo && uv run pytest -m "not integration"`
- Live integration: `cd services/topo && CH_HOST=<ip> CH_PASSWORD=<pw> JUNOS_MCP_URL=… JUNOS_MCP_TOKEN=… JUNOS_DEVICES=vsrx-br05 uv run pytest -m integration`
- One collection cycle: `cd services/topo && uv run python -m ssdf_topo.collect_all`
- One resolver pass: `cd services/topo && uv run python -m ssdf_topo.resolve_main`
- Deployed: collectors+resolver on Proxmox LXC **ct109** (`ssdf-topo`, 198.51.100.153, no
  Docker) on a 5-min systemd timer (`ssdf-topo.timer` → oneshot collect→resolve); writes CH
  ct104 as `ssdf_topo`. Topology MCP tools (`get_entity`, `locate`, `neighbors`, `find_path`,
  `enforcement_points`, `topology_snapshot`) live on the existing `ssdf-mcp-query` (ct106).
  As-built coords in gitignored `services/topo/infra/ENV.local`.
- **Firewall-role device nodes (M6c, issue #6 scope A).** The junos + panos collectors self-emit one `device_inventory(role=firewall, name=<device>)` observation per device (helper `collectors/base.py:firewall_inventory`), so `panosvm`/`vsrx-br05` resolve as `kind=device, attrs.role=firewall` and `enforcement_points` can attribute them. Requires `JUNOS_DEVICES` to be set on ct109 (`/etc/ssdf-topo/ENV.local`) — junos collector is a no-op with an empty device list.
- **Collector MCP arg names (latent-bug fix, M6c; re-broken by the 2026-08-15 vendor-MCP rename, fixed 2026-08-19):** `execute_junos_command` takes `router_name` (NOT `router`); PAN-OS is now `execute_panos_op(device, command)` / `get_panos_config(device)` (was `execute_pan_op(host, cmd)` / `get_pan_config(host)`). Wrong names raise a tool error, which `run_collectors` catches and silently skips — surfaced only when a collector runs live. Contract tests in `services/{topo,policy,health}/tests` now pin the tool + argument names so a rename fails in CI instead of silently zeroing a vendor.

### M6a (entity/correlation — services/entity + explain_access tool)
- Entity unit tests: `cd services/entity && uv run pytest -m "not integration"`
- Entity live integration (writes CH): `cd services/entity && CH_HOST=<ip> CH_USER=ssdf_entity CH_PASSWORD=<pw> uv run pytest -m integration`
- mcp-query unit tests (incl. entitystore/access_tools): `cd services/mcp-query && uv run pytest -m "not integration"`
- One resolver pass: `cd services/entity && uv run python -m ssdf_entity.resolve_main`
- One reconcile pass (merge+delete stale ip_only twins): `cd services/entity && uv run python -m ssdf_entity.reconcile_assets`
- Apply entity schema + user: `clickhouse-client < infra/clickhouse/004_entities.sql` then `ENTITY_PW=<pw> envsubst < infra/clickhouse/005_entity_user.sql | clickhouse-client`.
- Deployed: resolver on Proxmox LXC **ct109** (shares host with M4 topo; venv `/opt/ssdf-entity`, env `/etc/ssdf-entity/ENV.local` mode 600) on a 5-min systemd timer (`ssdf-entity.timer` → oneshot `ssdf-entity.service`); writes CH ct104 as `ssdf_entity` into `ssdf.entities`/`ssdf.entity_edges`. The `explain_access(client, server)` MCP tool lives on `ssdf-mcp-query` (ct106), reading as `ssdf_ro`. As-built coords in gitignored `services/entity/infra/ENV.local`.
- **ClickHouse `toString(col) AS col` alias trap:** aliasing a `toString(...)` back to the source column name shadows the real typed column in WHERE/ORDER BY, turning datetime comparisons into lexical string compares. Qualify the column (e.g. `entity_edges.last_seen`) in filters. (Bug found in M6a live validation; see STATUS.md.)
- **Segment-scoped asset identity (asset-duplication fix).** MAC is identity; IP is a per-vantage observation. Asset key is `mac:<mac>` when an ARP binding for the flow's firewall segment binds IP→MAC, else the segment-local fallback `ip:<segment>:<ip>` (was a global `ip:<ip>` that duplicated whenever the same IP sometimes did/didn't bind a MAC). `normalize_segment(name)` = first dotted label lowercased, so flow-side `observer_hostname` (FQDN) and binding-side `source_device` (short name) agree (`panosvm.example.com`→`panosvm`). A binding map `(segment, ip)→mac` is read from `topo_observations` arp_entry over `TOPO_BINDING_LOOKBACK_HOURS` (default 168h), latest-observation-wins; same IP+different MAC in one segment flags `ip_conflict` and never merges; same IP across segments stays distinct (NAT/branch reuse). The `COMMUNICATED_WITH` edge is keyed on **entity ids** (not raw IP pairs), so two IPs collapsing to one MAC share one edge and accumulate stats.
- **Reconcile pass (`reconcile_assets`).** Standalone idempotent cleanup for twins already written before the fix: merges a stale ip_only twin's COMMUNICATED_WITH edge attrs into the MAC asset's edge, then `ALTER TABLE … DELETE` (mutations_sync=1) the twin + its edges — only when the IP maps to exactly one MAC and that MAC asset exists. Twin GOVERNED_BY edges are dropped (not re-pointed) and re-derived by the next resolver pass.
- **`find_entity` confidence-first ordering.** By-IP lookups can match both a MAC asset (confidence 1.0) and a stale ip_only twin (0.5); `ORDER BY confidence DESC, entities.last_seen DESC` makes the MAC asset win so explain_access reads its `observer_hosts`-bearing edge (fixes the M6c-B provenance caveat where a by-IP lookup returned the stale twin).

- **Per-device resilience (2026-08-19):** the junos collectors in `policy` and `health` now
  skip an unreachable device and continue the fleet (matching `topo`'s long-standing pattern).
  `run_collectors` catches at *collector* granularity, so one bad device previously discarded
  every other device's rules/gauges — live, a single stale `known_hosts` entry zeroed all 23.

### M6b (configured policy — services/policy + explain_access configured_controls)
- Policy unit tests: `cd services/policy && uv run pytest -m "not integration"`
- Live integration (needs CH + vendor MCPs): `cd services/policy && CH_PASSWORD=<pw> PANOS_MCP_URL=… PANOS_MCP_TOKEN=… JUNOS_MCP_URL=… JUNOS_MCP_TOKEN=… JUNOS_DEVICES=vsrx-br05 uv run pytest -m integration`
- One pass: `cd services/policy && uv run python -m ssdf_policy.collect_resolve`
- Deployed: collector+resolver on ct109 (third role alongside topo+entity; venv `/opt/ssdf-policy`, env `/etc/ssdf-policy/ENV.local` mode 600) on an HOURLY systemd timer (`ssdf-policy.timer` → oneshot `ssdf-policy.service`); writes CH ct104 as `ssdf_entity` into the shared `ssdf.entities`/`ssdf.entity_edges` (kind='firewall'|'policy', source='configured'). `explain_access` (ct106) gains `configured_controls` + integer `coverage.configured`. As-built coords in gitignored `services/policy/infra/ENV.local`.
- Configured Policy is keyed `provider:device_name:rule_name` (per-firewall identity — fixes M6a's same-name collapse where two firewalls' identically-named rules merged); Firewall entities keyed `device:<name>` linked by `Firewall──GOVERNED_BY(configured)──►Policy` edges.
- Device names in `JUNOS_DEVICES`/`PANOS_DEVICE` MUST match M4 `source_device` names so explain_access can bridge topology firewalls → Firewall entities by name.
- Junos rules read via `execute_junos_command "show configuration security policies | display set"`; PAN-OS via `get_panos_config` (vsys1 security rulebase, pinned to 12.1 config shape). `get_panos_config` nests its payload as `{"output": {"content": "<xml>"}}` — `collectors/panos.py:_root` unwraps that and the older flat `{"result": ...}`.
- **M4↔M6b name-bridge gap (live finding):** `explain_access` attaches configured rules to a path via M4 `enforcement_points`, which only returns graph nodes with `kind=="device"` AND `attrs.role=="firewall"`. M4 currently models **0** such nodes, so live `explain_access` on real transit pairs returns `configured_basis:no_path_firewall` and `coverage.configured:0` even though the configured side is correct (direct `configured_policies_for_firewalls(["panosvm","vsrx-br05"])` returns all 6 policies). Closing this needs M4 to emit firewall-role device nodes; tracked as the M6b→M4 dependency in issue #6 (milestone M6c). **Closed by M6c scope A (PR #7 — M4 now emits firewall-role nodes, fixing the topology/fallback path) + M6c scope B (provenance attribution as the primary, transit-robust path; below).**

### M6c scope B (provenance firewall attribution — observer_hostname → explain_access)
- Apply migration: `clickhouse-client < infra/clickhouse/006_observer_hostname.sql` (idempotent `ADD COLUMN IF NOT EXISTS observer_hostname LowCardinality(String)` on `ssdf.events`).
- Run Vector unit tests (validate `observer_hostname` emission): on ct102, `vector test infra/vector/vector.toml` — the `srx_observer_hostname_from_syslog_host` + `panos_observer_hostname_from_syslog_host` tests assert it from the syslog HOSTNAME.
- entity unit tests (flow-agg `observer_hosts` + edge attr): `cd services/entity && uv run pytest -m "not integration"`.
- mcp-query unit tests (provenance-primary attribution): `cd services/mcp-query && uv run pytest -m "not integration"`.
- **Mechanism:** the firewall that *logged* a flow is by definition on its path. `observer_hostname` (ECS `observer.hostname`) is normalized at ingest (both `srx_ecs` + `panos_ecs` transforms emit `string(parsed.hostname)`); the entity resolver collects it per pair via `groupUniqArray(observer_hostname)` in `build_flow_agg_sql` and merges it onto the `COMMUNICATED_WITH` edge as a comma-set `observer_hosts`; `explain_access` reads `observer_hosts` first → `firewall_basis:provenance`, falling back to M4 `enforcement_points` only when absent (`firewall_basis:topology`/`no_path_firewall`). New response field: `firewall_basis`.
- **Live proof:** resolve the client by an identifier that lands on the flow-owning asset (`explain_access("203.0.113.1"` server, client = the MAC/asset that owns the flow) → `firewall_basis:provenance`, `firewalls:[vsrx-br05]`, `coverage.configured:1`).
- **Proof caveat (pre-existing M6a duplication):** an IP that sometimes binds a MAC (M4 topo) and sometimes doesn't yields TWO Asset entities; `find_entity` orders `last_seen DESC LIMIT 1`, so a by-IP lookup can return a stale ip-only asset whose edge lacks `observer_hosts`. This is M6a's IP-vs-MAC identity split, not a scope-B defect. vsrx-br05 is the live-proven path.
- **Provenance suffix normalization (M6c-B follow-up):** `explain_access` normalizes each `observer_hosts` value to its first DNS label (`access_tools._short_host` — case-preserved, IPv4/IPv6-guarded) before matching Firewall entities, so PAN-OS `panosvm.example.com` bridges to `device_name=panosvm`. vSRX (`vsrx-br05`, dot-free) is a no-op, so the live-proven path is unchanged. Side effect: the `firewalls` response field is now vendor-consistent (short device names for both vendors). Unit-proven (`test_short_host`, `test_explain_access_provenance_normalizes_panos_fqdn`, `test_explain_access_provenance_preserves_mixed_case_short_name`); NOT yet live-proven end-to-end — no PAN-OS transit flow exists in the lab (same M5/M6c-B carve-out). Spec: `docs/superpowers/specs/2026-06-10-ssdf-panos-provenance-suffix-normalization-design.md`.

### M7a (classification + multi-principal auth + audit — ssdf-mcp-query hardening)
- Unit tests: `cd services/mcp-query && uv run pytest -m "not integration"` (adds classification/auth/audit/wrapper/server-audit suites).
- Live audit integration: `cd services/mcp-query && CH_HOST=<ip> CH_PASSWORD=<ro_pw> CH_AUDIT_PASSWORD=<audit_pw> [CH_ADMIN_PASSWORD=<pw>] uv run pytest -m integration`.
- Apply audit schema + user: `AUDIT_PW="$CH_AUDIT_PASSWORD" envsubst < infra/clickhouse/007_audit.sql | clickhouse-client --host <ct104> --multiquery` (creates `ssdf.audit` + INSERT-only `ssdf_audit`; pattern mirrors `005_entity_user.sql`).
- **Multi-principal auth:** set `MCP_TOKENS_FILE` (JSON keyed by **digest**: `{ "sha256:<hex>": {"principal": "...", "allowed_tools": [...]} }`; omit `allowed_tools` ⇒ all tools). **Tokens are stored as SHA-256 digests, never plaintext (issue #7, 2026-08-27).** `DigestTokenVerifier` hashes what the caller presents and matches that — FastMCP's `StaticTokenVerifier` cannot do this (it keys a dict by the plaintext, and its own docstring says "Never use this in production"). Mint with `python -m ssdf_mcp_query.mint_token --principal <name> [--allowed-tools a,b] [--days 90]`; the token prints ONCE and is not recoverable. The loader **refuses a group/world-readable token file** at startup. A legacy plaintext key still loads (hashed on read) but names its principal in a stderr warning — re-mint those and treat them as compromised, since a leaked token is indistinguishable from a live one. Format notes: `services/mcp-query/infra/tokens.README.md`. Leaving it unset keeps the single-token path (`MCP_AUTH_TOKEN`/`MCP_TOKEN_FILE`) mapped to principal `agent`/all-tools. Example: `services/mcp-query/infra/tokens.example.json`. **`local_only` gate (M16e):** a `tier="sovereign"` build now drops any token lacking `"local_only": true` from the verifier before auth runs — the sovereign tier is for local models only, so a hosted-model credential (e.g. an eval-runner principal) cannot authenticate against it regardless of what it claims elsewhere. This is **not backward-compatible**: ct106's existing `tokens.json` predates the field, so every entry in it needs `--local-only`-minted replacement (or the field added by hand) before this ships, or sovereign auth on ct106 goes dark. `tier="public"` is unaffected.
- **Classification:** secure-by-default; only `topology`/`identity` are configurable to `shareable` via `MCP_CLASSIFICATION_FILE`. Overriding `security_log`/`firewall_config`, an unknown class, or a bad value ⇒ `ConfigError` at startup (fail closed). M7a only *labels*+*audits* — it never withholds data (that is M7b). Example: `services/mcp-query/infra/classification.example.json`.
- **Caller attribution (issue #9, 2026-08-27):** `ssdf.audit` also carries `client_name` / `model_id` / `actor_type` (migration `017_audit_attribution.sql`, all `String DEFAULT ''`). **Trust levels differ and are not interchangeable:** `client_name` is CLIENT-ASSERTED (MCP `clientInfo`, a client may claim anything); `model_id` and `actor_type` are OPERATOR-DECLARED (read from the token entry, so they need token-file write access). `actor_type` is constrained to human|agent|unknown — an unrecognised value reads as `unknown` rather than being stored verbatim. **Hash chain:** `audit_chain.canonical()` appends the three fields ONLY when one is non-empty, so pre-017 rows and mecmcp's `tier="evidence"` rows still serialise to the original nine-element form and verify unchanged — no coordinated release, and no backfill (a row that had no attribution genuinely had none). Attribution IS inside the tamper-evidence: rewriting `model_id` breaks verification, proven live on CH 24.8. `verify_audit._VERIFY_COLUMNS` MUST select the three columns or it recomputes the wrong form. Contract: `docs/audit-evidence-contract-v1.md`.
- **Audit path:** every tool call writes one `ssdf.audit` row (ts, principal, tier=`sovereign`, tool, args-JSON, data_classes, decision allow|deny, row_count, error) as the `ssdf_audit` user on a connection SEPARATE from the `ssdf_ro` query path. Audit is best-effort — an insert failure is logged to stderr but never fails the tool call. A disallowed tool returns `{"error":"forbidden"}` (HTTP 200) and audits `decision="deny"` without invoking the tool. `CH_AUDIT_PASSWORD` unset ⇒ no-op auditor (server still runs) UNLESS `MCP_AUDIT_REQUIRED=1` (set on both shipped units, `ssdf-mcp-query.service` + `ssdf-mcp-public.service`), which instead refuses to start (fail-closed) — see `make_ch_auditor` in `audit.py`.
- **Per-principal limits (issue #8, 2026-08-27):** `MCP_MAX_CALLS_PER_MINUTE` + `MCP_MAX_CONCURRENT_CALLS`, both default **0 = off** (an unconfigured deploy is unchanged). Enforced in `wrapper.audited_tool` via `ratelimit.PrincipalLimiter`, keyed on the authenticated principal — nginx's limits are per-IP (`$binary_remote_addr`), so agents behind one address share a bucket and no single token can be throttled. Both layers stay: nginx is the cheap per-address flood defence, this is per-identity fairness. A throttled call returns `{"error":"rate_limited"}` (NOT `forbidden` — throttling is transient, an authz denial never becomes permitted) and audits `decision="deny"`, so "was it throttled" is a question `ssdf.audit` answers. Limits are per-process, so per-tier by construction. Order matters: authz is checked BEFORE throttling, so a principal that may not call a tool is told that rather than blamed on load.
- **Per-tool wrapper:** `wrapper.audited_tool` wraps each tool with `functools.wraps`, so FastMCP's schema (built via `get_type_hints`+`inspect.signature`) still sees the real tool signature/docstring. Tool return shapes are unchanged (agents already bind to them).
- ct106 is an editable install at `/opt/src/mcp-query/src` — sync source + `systemctl restart ssdf-mcp-query.service`; add `MCP_TOKENS_FILE`/`MCP_CLASSIFICATION_FILE`/`CH_AUDIT_USER`/`CH_AUDIT_PASSWORD` to `/etc/ssdf-mcp/…` (mode 600).
- **Hands to M7b:** `classification.py` (taxonomy+map), `audit.py`+`ssdf.audit` (public process writes `tier="public"`), and the token-map auth pattern. Classes flagged `shareable` drive M7b's shareable views + `ssdf_public` grants.

### M7b (public MCP split — ssdf-mcp-public tier)
- Unit tests: `cd services/mcp-query && uv run pytest -m "not integration"` (adds `test_server_public` + classification/graphstore public-schema suites).
- Live floor/audit integration: `cd services/mcp-query && CH_HOST=<ip> CH_PUBLIC_PASSWORD=<pub_pw> CH_AUDIT_PASSWORD=<audit_pw> CH_PASSWORD=<pub_pw> [CH_ADMIN_PASSWORD=<pw>] uv run pytest tests/test_public_views_integration.py -m integration`.
- Apply public views + users: `DEFINER_PW="$CH_DEFINER_PASSWORD" PUBLIC_PW="$CH_PUBLIC_PASSWORD" envsubst < infra/clickhouse/008_public_views.sql | clickhouse-client --host <ct104> --multiquery` (creates `ssdf_public` db, `ssdf_view_definer`, two `SQL SECURITY DEFINER` views, and the `ssdf_public` reader granted on views only).
- **Tier select:** the SAME `ssdf_mcp_query.server` runs public when `MCP_TIER=public` (default `sovereign`). Public build registers only tools whose data classes are ALL `shareable` (per `MCP_CLASSIFICATION_FILE`), **minus `run_sql`** (hard-excluded). No shareable class ⇒ 0 tools + a stderr warning (secure default). Public stores read the `ssdf_public` schema (`graphstore` `schema` param); audit rows are tagged `tier="public"`.
- **Hard floor:** `ssdf_public` has SELECT on `ssdf_public.graph_nodes`/`graph_edges` ONLY; the definer views read base `ssdf.*` as `ssdf_view_definer`. `ssdf_public` selecting any base `ssdf.*` table ⇒ `ACCESS_DENIED` (proven by `test_public_cannot_read_sovereign_base_tables`).
- **Deployed:** guest **703** `ssdf-mcp-public` (was ct113; 198.51.100.154, port 30033) on pve2 — mirrors 702 (ct106) (pip editable venv `/opt/ssdf-mcp` over `/opt/src/mcp-query`, deployed from `main`, NOT copied from ct106 which still runs M7a). Unit `services/mcp-query/infra/ssdf-mcp-public.service`; `/etc/ssdf-mcp/secrets.env` (mode 600) holds `CH_PASSWORD`=ssdf_public pw + `CH_AUDIT_PASSWORD`; `/etc/ssdf-mcp/classification.json` flips `topology`/`identity` to `shareable` (see `infra/classification.public.example.json`). A public LLM connects as an MCP client to `http://198.51.100.154:30033/mcp` with a public-tier token — MCP is the only interface; no API/egress to configure. **VMID note:** the design said ct110 but VMID 110 is the `vSRX-test1` VM — the container is **ct113** (hostname/IP/port unchanged). Auditor connects with default-db `ssdf_public` but inserts to fully-qualified `ssdf.audit` (the `ssdf_audit` grant covers it).

### P0 ingest hardening (H1 nftables allow-list + H2 observer_hostname device gate)
- Security-review P0 fixes from `docs/security/2026-06-10-vulnerability-review.md` (findings H1+H2); spec `docs/superpowers/specs/2026-06-10-ssdf-p0-ingest-hardening-design.md`, plan `docs/superpowers/plans/2026-06-10-ssdf-p0-ingest-hardening.md`. PR #15 (merged `0156368`); both DEPLOYED + verified live on ct102 2026-06-10.
- **H1 (nftables source allow-list on the ingest host):** apply with `./scripts/apply_ct102_nftables.sh` (idempotent; env `PVE_HOST_SSH` (now `root@pve2.example.com`), `SSDF_VECTOR_CTID` (now `700`)). Rule file `infra/firewall/ct102-ingest.nft` → pushed to ct102 `/etc/nftables.d/ssdf-ingest.nft`; dedicated `inet ssdf_ingest` table accepts UDP 514/515 only from `198.51.100.220-198.51.100.242` (vSRX test fleet + panosvm .225) and drops everything else on those ports. Base chain `policy accept` ⇒ all other traffic passes; the default `inet filter` table is untouched. Flat /24 LAN means interface-binding can't isolate senders, so source-IP filtering is required. Verify: `ssh root@pve2.example.com "pct exec 700 -- nft list table inet ssdf_ingest"` shows both rules; `include "/etc/nftables.d/ssdf-ingest.nft"` in `/etc/nftables.conf` makes it reboot-persistent. Revert: `nft delete table inet ssdf_ingest`.
- **H2 (known-device gate, both VRL transforms):** `srx_ecs` + `panos_ecs` in `infra/vector/vector.toml` now gate `observer_hostname` — normalize the syslog HOSTNAME to its first DNS label, lowercase **for the membership test only**, accept iff `panosvm` (exact) or regex `^vsrx-test\d`, else blank to `""`. **Stored value keeps original case** so the M6c-B `vsrx-br05` exact-match provenance bridge in `explain_access` is intact. Defense-in-depth for spoofed-but-source-allowed packets. Tests (run on ct102): `vector test infra/vector/vector.toml` — 14/14 incl. `srx_observer_hostname_unknown_is_blanked`, `panos_observer_hostname_unknown_is_blanked` (unknown HOSTNAME ⇒ `observer_hostname==""`) plus regression that known hosts pass through.
- **H2 live deploy (gated on ClickHouse being reachable):** Vector's CH-sink healthcheck fails if ct104 is down, so deploy when CH is up. Push the updated toml, `vector validate /etc/vector/vector.toml.new` (CH healthcheck must pass), back up the old config, `mv` into place, `systemctl restart vector.service`, confirm `active` + both UDP sources listening. Vector config path on ct102 is `/etc/vector/vector.toml`; env drop-in sets `CH_HOST` + `VECTOR_CONFIG`.
- **Remaining review backlog:** ALL CLOSED — P1 (M1/M3/M4/M5/M6) via PR #16 (deployed 2026-06-11/12), M2 + L1–L6 via the edge-hardening batch below. See STATUS.md "Security hardening backlog".

### P1 in-place hardening (M1/M3/M4/M5/M6 — PR #16, deployed)
- CH query caps live in `clickhouse.py` `run()` (`MCP_MAX_EXEC_SECS`/`MCP_MAX_RESULT_ROWS`/`MCP_MAX_MEMORY_BYTES`); **migration `010_ro_settings_constraints.sql` is required** — readonly=1 users reject per-query settings unless declared `CHANGEABLE_IN_READONLY` with MAX bounds (live-found).
- Audit hash chain: `audit_chain.py` (per-tier `row_hash = SHA256(prev_hash + canonical(row))`); offline verifier `uv run python -m ssdf_mcp_query.verify_audit` (reads as `ssdf_audit_verify`, needs `CH_AUDIT_VERIFY_PASSWORD` + base CH/token envs; exit 0 clean / 1 issues / 2 config). Pre-009 rows (`row_hash=''`) are legacy chain-starts, excluded by design.
- systemd: all 5 units run `DynamicUser=yes` + hardening block. **DynamicUser cannot read root-owned 600 secrets** — units use `LoadCredential=` + `%d/...` paths (live-found). Tokens/classification now via `LoadCredential=tokens.json:/etc/ssdf-mcp/tokens.json` → `MCP_TOKENS_FILE=%d/tokens.json`.

### Edge hardening (M2 + L1–L6 — TLS, nginx edge, token expiry, grant split)
- Spec: `docs/superpowers/specs/2026-06-11-ssdf-edge-hardening-design.md`. All deployed + live-verified 2026-06-12.
- **PKI:** `./scripts/gen_ssdf_tls.sh` → gitignored `infra/tls-local/` (CA 10y + ct104/ct106/ct113 leaves 825d, IP SANs). CA key never leaves the dev host; only `ssdf-ca.crt` is distributed. Re-issue leaves: `--force`.
- **CH TLS (ct104):** apply with `./scripts/apply_ct104_tls.sh` — https 8443 (`config.d/ssdf-tls.xml`), nftables `inet ssdf_ch` closes plaintext 8123/9000 to loopback-only (container-local admin still works). Clients opt in via `CH_PORT=8443 CH_SECURE=1 CH_CA_FILE=<ca>` (same envs across mcp-query/topo/entity/policy and the integration tests). **Trap:** clickhouse-connect infers https from port 8443 even without `interface=` — stale code on a host then fails cert-verify instead of falling back.
- **Vector (ct102):** endpoint is `${CH_PROTO:-http}://${CH_HOST}:${CH_HTTP_PORT:-8123}` (env-nesting inside defaults does NOT parse — proven Vector 0.56.0). Live host sets `CH_PROTO=https CH_HTTP_PORT=8443` in the systemd drop-in and appends `[sinks.clickhouse.tls] ca_file="/etc/vector/ssdf-ca.crt"` to the deployed toml (a checked-in tls block would break the plain-http default).
- **nginx MCP edge (ct106/ct113):** apply with `./scripts/apply_mcp_edge.sh` — TLS on LAN 30032/30033, uvicorn rebound to `127.0.0.1:31032/31033` via drop-in `edge.conf`; rate limit 10r/s burst 30 + 32 conns/IP (429), Host gate (444), Origin gate (403), SSE-safe proxying. Clients now use `https://198.51.100.152:30032/mcp` / `https://…154:30033/mcp` with `ssdf-ca.crt` trust (Claude Code: `NODE_EXTRA_CA_CERTS`).
- **Token expiry/rotation:** `tokens.json` entries take optional `"not_after": "<ISO-8601 UTC>"` — enforced per call in `wrapper` (expired ⇒ `{"error":"forbidden"}` + audit deny); malformed ⇒ fail-closed. Rotation: add new entry → restart → move clients → delete old → restart. Both tiers run named principals with +90d expiry; local client config in gitignored `.mcp.json`.
- **L4 grant split:** `ENTITY_MAINT_PW=… envsubst < infra/clickhouse/011_entity_maint_user.sql | clickhouse-client --multiquery` — reconcile runs as `CH_USER=ssdf_entity_maint python -m ssdf_entity.reconcile_assets`; the 5-min resolver identity `ssdf_entity` no longer holds ALTER DELETE.
- **PAN-OS timestamps fixed to UTC (P2, 2026-06-12):** panosvm now runs `timezone UTC`
  (onboarding/panos/timezone-utc.md) and pre-cutover rows were backfilled +4h
  (`infra/clickhouse/012_backfill_paloalto_utc.sql.example`, cutover 2026-06-12 12:00:00 UTC —
  chosen by boundary inspection in a row-free gap, NOT the commit time; see 012).
  Any NEW log source must be onboarded with a UTC device clock — naive-parse skew otherwise.

### Ops (backups + lab traffic)
- **vzdump backups (P2, 2026-06-12; VMIDs corrected 2026-08-26):** the cluster already
  backs up every guest via `pve2-all-daily` / `pve3-all-daily` (all guests → `nas-backup`,
  keep-daily 14 / weekly 8 / monthly 12), verified live 2026-08-26 — **ClickHouse is
  covered, and `scripts/apply_pve_backup_job.sh` is NOT required.** That script adds two
  narrower, additive SSDF-only jobs on separate storage: `ssdf-ch-daily` (701, 03:30,
  keep-daily=7/weekly=4) and `ssdf-all-weekly` (700,701,702,703,704, Sun 04:30,
  keep-weekly=4); snapshot mode + zstd. Its VMIDs named the pre-renumber ct1xx guests
  until 2026-08-26, so running it then would have created two jobs backing up NOTHING —
  which reads as "backups configured" and is worse than a visible failure. `local` is a
  dir on the host's own disk: it covers container loss/fat-fingers, NOT host-disk loss;
  prefer NAS-backed storage. Schedule times are host-local. Verify with
  `pvesh get /cluster/backup`; restore-drill to a SCRATCH VMID only, never 701 itself.
- **Lab transit traffic (Phase 2, 2026-06-15):** TWO Alpine endpoints run the shared
  `scripts/labgen_endpoint.sh` daemon (OpenRC service `labgen`, not cron — it self-loops
  ~30s jittered) so BOTH firewalls can be live-proven as SSDF transit sources on demand:
  guest 710 `ssdf-traffic-gen-srx` (was ct198 `ssdf-ep-srx`; 192.0.2.20/24, gw 192.0.2.1) behind vsrx-prod trust VLAN 198,
  and guest 711 `ssdf-traffic-gen-panos` (was ct199 `ssdf-ep-panos`; 203.0.113.20/24, gw 203.0.113.1) behind panosvm trust VLAN 199.
  Trust VLANs are Proxmox-only bridge tags on vmbr1 (VLAN id = endpoint CTID, no UniFi net
  object). The generator produces permitted internet egress PLUS a deliberate denied DNS
  attempt (firewalls allow DNS only to approved resolvers 198.51.100.1/1.1.1.2/1.0.0.2;
  endpoints query 8.8.8.8 → deny event on both vendors). Runbooks:
  `onboarding/srx/transit-endpoint.md`, `onboarding/panos/transit-traffic.md`.
  **710/711 are normally STOPPED, and that is the intended resting state** — start them only
  when transit traffic logs are actually wanted, then stop them again. A stopped generator is
  not an outage and needs no action; it only means no new transit flows are being produced.
  Do not destroy them without replacing the source; neither is in the weekly backup job
  (reproducible from the runbooks). The old single-vendor ct115 (`labgen_transit.sh`, cron)
  was retired.
- **H2 device gate broadened (Phase 2):** the `infra/vector/vector.toml` observer_hostname
  gate now accepts `^vsrx-(test\d|production)` (was test-fleet-only), so vsrx-prod'vsrx-prod
  RT_FLOW events carry `observer_hostname=vsrx-prod` (original case preserved for the
  `explain_access` `device:vsrx-prod` provenance bridge). Unknown hosts still blank.

### M8 (agent evals — services/evals, SSDF side only)
- Unit tests + corpus lint: `cd services/evals && uv run pytest -m "not integration"`
- Live integration (corpus SQL validity + audit join): `CH_HOST=<ip> CH_PORT=8443 CH_SECURE=1 CH_CA_FILE=… CH_PASSWORD=<ro_pw> CH_AUDIT_VERIFY_PASSWORD=<av_pw> [CH_AUDIT_PASSWORD=<audit_pw>] uv run pytest -m integration`
- Score a run: `uv run python -m ssdf_evals.score <manifest.json>` (exit 0 scored / 2 config/contract/scoring error); regression gate: `uv run python -m ssdf_evals.regress results/<scorecard>.json` (exit 0 = no regressions / 1 = regressions listed on stderr / 2 = unreadable or schema-invalid scorecard).
- **Boundary:** this repo stops at the MCP layer — NO runner code, NO LLM-judge, NO new MCP tools, nothing deploys. External runner projects execute the corpus against the live MCP endpoints (prod https+token path) under a dedicated eval principal (`eval-*` in tokens.json) and hand back a run-manifest JSON (`services/evals/schemas/manifest.schema.json` = the contract). `ssdf.audit` is the only trusted tool trace.
- Scoring is 100% deterministic: `reference_sql` predicates compute ground truth against live CH **at scoring time** (live lab data — static answers would rot); `expected_json` for stable facts; `refusal` for honesty questions. Structured answers via per-question `answer_format` (verbatim prompt suffix) are what make this possible.
- Corpus: `golden/core.yaml` (33 questions, 5 categories, tier-tagged sovereign|public|both); lint enforced in unit tests (unique ids, public questions restricted to public tools, SELECT-only SQL). Scorecards committed under `services/evals/results/` — git history is the eval database.
- **Corpus live-fixes:** configured-policy questions filter `identifiers['provider']`/`identifiers['device_name']` (live entity_ids are 16-hex hashes, not natural keys); the panosvm policy count uses `count(DISTINCT entity_id)` (ReplacingMergeTree duplicate-version trap).
- **Audit-check integrity:** `started`/`finished` + principal are trusted from the manifest — this only holds if the runner uses a **dedicated eval-only principal** (e.g. `eval-claude`, `eval-qwen`) that is never shared with regular agents or other runners. Serial reuse across runs is fine; two runs must never execute concurrently (or with overlapping ±slop audit windows) under the same principal — otherwise the audit tool-check window is untrustworthy and SSDF will not vouch for the scorecard. Add eval principals to ct106/ct113 tokens.json at first run.
- **External runner (the other half of M8, NOT in this repo):** the runner is the standalone sibling repo `~/ssdf-eval-runner/` (its own git — never merge runner code into SSDF). Pure `core` (corpus load/tier-filter/prompt build/JSON extraction/manifest assemble+validate) + two adapters: `claude_adapter` shells `claude -p --output-format json --mcp-config <f> --strict-mcp-config --allowedTools "mcp__ssdf__*" --permission-mode bypassPermissions --no-session-persistence` (the CLI owns MCP; `NODE_EXTRA_CA_CERTS=<ca>` for CA trust; uses the CLI's OAuth — no `ANTHROPIC_API_KEY`); `qwen_adapter` drives MCP itself via `streamable_http_client(url, http_client=httpx.AsyncClient(verify=ssl_ctx, headers=...))` (the factory path `streamablehttp_client` can't inject CA `verify=`) + an Ollama tool loop. Run: `SSDF_ROOT=… ssdf-eval-run --model {claude,qwen} --tier {sovereign,public} --out <f>` with eval tokens sourced from `services/evals/infra/ENV.local`. **First full matrix ran 2026-06-13** → 4 committed scorecards (claude sov 16/22 + pub 4/6; qwen sov 4/22 + pub 1/6); see STATUS.md M8. The corpus sovereign run is **27 questions** (26 sovereign-tagged + 1 both), public is **7** (6 public-tagged + 1 both) — counts verified against `golden/core.yaml` on 2026-08-27; the scorecards above predate later corpus growth, so their denominators are smaller.
- **Coverage for the four late-added tools (2026-08-27):** `ingest_status`, `fabric_status`, `recent_alerts` and `lab_topology_snapshot` were served but absent from `corpus.SOVEREIGN_TOOLS`, so the lint rejected any question naming them and they had NO eval coverage. Registry fixed in v0.1.1; questions added as `change-ingest-live-firewalls`, `change-fabric-active-providers`, `flows-alert-providers-24h`, `topo-lab-device-count`. Each reference_sql was executed against the live fabric when written. **`recent_alerts` cannot answer a count question** — it returns bounded rows (limit clamped 2000) behind a Python-side `min_severity` floor defaulting to `high`, so its question asks which providers alerted, not how many alerts there were.
- **Scorecards are stale (last run 2026-06-20).** Re-running the matrix needs the external runner repo `~/ssdf-eval-runner/`, which is NOT present on this workstation, plus eval tokens in the gitignored `services/evals/infra/ENV.local`. Authoring corpus questions does not require either; running them does.
- **Sovereign tier is local-model-only (M16, M16e).** `eval-claude`'s `claude_adapter` shells the hosted Claude Code CLI — a hosted-model runner holding a sovereign token, which is exactly how real lab RFC1918 addresses and rule names leaked into committed scorecards via live `reference_sql` predicate lookups (scrubbed at HEAD; git history is a separate board decision). Two independent gates now close this: (1) `manifest.schema.json` requires `local: bool`; `score_run` refuses (`SovereigntyError`, exit 2, no scorecard written) any `tier: sovereign` manifest with `local: false` — see `ssdf_evals.sovereignty`. (2) `services/mcp-query` tokens now take an optional `local_only: bool`; a `tier="sovereign"` build drops any token lacking it from the verifier before auth runs, so a hosted-model credential can't authenticate against ct106 regardless of what its manifest claims. **Only `eval-qwen` (local Ollama via `qwen_adapter`) should be re-minted with `--local-only` for ct106; `eval-claude` should NOT be** — its sovereign access should stay dead until/unless the runner points it at a local model. See `services/mcp-query/infra/tokens.README.md`.

### M9 (UniFi Gateway Max Suricata IPS ingest — Vector CEF → ClickHouse)
- SSDF's first **detection-class** source (prior sources SRX/PAN-OS were flow/traffic). UniFi Gateway Max Suricata IPS/IDS alerts ingest via remote syslog on Vector ct102 UDP **port 516** (SRX=514, PAN-OS=515, each a separate source to avoid collision) → `ssdf.events`. Merged to `main` (merge `818a984`); **end-to-end live-proven 2026-06-14**.
- Run Vector unit tests (on ct102 where Vector is installed): `ssh root@pve2.example.com "pct exec 700 -- bash -c 'cd /etc/vector && vector test vector.toml'"` — 20/20 incl. the UniFi CEF suite. Validate locally (syntax only): `CH_HOST=127.0.0.1 vector validate --no-environment infra/vector/vector.toml`.
- **Wire format is CEF (Common Event Format), NOT Suricata EVE-JSON** (the original synthetic baseline was wrong). Lines look like `CEF:0|Ubiquiti|UniFi Network|<ver>|200|Threat Detected|<sev>|<ext>`, carry NO syslog PRI. Sender is the **Cloud Key controller `198.51.100.30`** (host `UCK-G2-Plus-site-controller`) forwarding the SIEM export — NOT the Gateway Max `198.51.100.1` (which only emits RFC3164 system-log noise on the same port, dropped by the filter).
- VRL: `[transforms.unifi_cef_threat]` filter gates on `CEF:0|Ubiquiti` + `|Threat Detected|` before `[transforms.unifi_ips]`, which parses via **`parse_cef`** (NOT regex/key-value — CEF extension values contain spaces and Rust regex has no lookahead). Re-validate the transform on any UniFi Network upgrade that changes the CEF schema. **The controller has since upgraded: DeviceVersion observed on the wire is 10.69.67 (was 10.68.57), and the threat path is UNVERIFIED on that version** — no `|Threat Detected|` event has been ingested in 30 days, and an attempt to trigger one on 2026-08-19 (benign ET POLICY 2013054 pycurl-UA request rather than the runbook's third-party port sweep) produced no detection; `get_flow_risks(min_risk_level=medium)` also returns empty, so the likeliest reading is simply that nothing is being detected. The forwarding path itself is confirmed alive — client-state CEF (`403 Wired Client Connected` / `404 Wired Client Disconnected`) arrives at Vector continuously and is dropped by the `|Threat Detected|` gate, which matches on substrings and is therefore version-agnostic. What cannot be confirmed without a real detection is whether 10.69.67 changed the threat record's extension keys. Those client-state events are also an untapped device-liveness source (see issue #26).
- **No MAC columns in `ssdf.events`** + `skip_unknown_fields=false` ⇒ MACs/aliases/zones/signature detail go in `ext` (keys `unifi.ips.*`, `unifi.src_mac`, etc.). Detections carry MAC + alias only (no client IPs) → source_ip/destination_ip stay null. Event time from `UNIFIutcTime` (clean ISO-8601 UTC, trailing Z — no clock backfill needed).
- nftables ct102 ingest allow-list: UDP/516 source must be **198.51.100.30** (the controller). Apply with `./scripts/apply_ct102_nftables.sh` (rule file `infra/firewall/ct102-ingest.nft`).
- **Trailing-newline live bug (caught only on the wire):** the real UDP datagram is newline-terminated; the `$`-anchored CEF slice regex with default non-dotall `.` never reaches end-of-haystack past the trailing `\n`, so every real event hit `parse_error` while `vector test` (newline-stripped `insert_at` fixtures) passed. Fix: `strip_whitespace(raw)` before the regex + a `unifi_cef_trailing_newline_still_parses` regression test (TOML `'''…\n'''` literal keeps the newline). Lesson: socket sources deliver the trailing newline that `insert_at`/stdin fixtures silently drop.
- **Live trigger = behavioral ET SCAN rules** (outbound port-sweep to a routable range, e.g. Linode 45.33.x) — payload tests (EICAR/testmyids/GPL SIDs) do NOT fire (ruleset is ET-only + hardware flow-offload bypasses DPI). Detections lag ~60-90s. Live-proven SIDs: 2003068 (SSH scan), 2013479 (terminal-server), 2013054 (pycurl UA).
- ct106 surfaces detections: the `detections` field on `explain_access` + the `alerts_for_pair` store method read UniFi IPS alerts. Runbook (real captured samples in §3/§4): `onboarding/unifi/ips-syslog.md`.

### M11 (Proxmox host audit ingest — rsyslog RFC5424 → Vector → ClickHouse)
- The pve3 hypervisor host's **auth + admin-action audit stream** (logins + VM/CT task ops) as an SSDF event source. rsyslog on pve3 forwards `auth`/`authpriv`/`daemon` facilities **RFC5424** to Vector ct102 UDP **517** (514=SRX, 515=PAN-OS, 516=UniFi — each a separate source). → `ssdf.events` (`event_provider=proxmox`). **Ingest-only:** no new MCP tool, no schema migration — queryable via the generic `run_sql`/`describe_schema` tools. Merged on branch `m11-proxmox-ingest`; **end-to-end live-proven 2026-06-14**.
- Run Vector unit tests (on ct102): `ssh root@pve2.example.com "pct exec 700 -- bash -c 'cd /etc/vector && CH_HOST=127.0.0.1 vector test vector.toml'"` — 31/31 incl. the 11-test proxmox suite. Validate locally: `CH_HOST=127.0.0.1 vector validate --no-environment infra/vector/vector.toml`.
- **Transport is `parse_syslog` (RFC5424 with PRI + offset), NOT the UniFi CEF regex-slice.** rsyslog forwards `;RSYSLOG_SyslogProtocol23Format`, whose ISO-8601 timestamp carries the UTC offset — so SSDF stores correct UTC **even though pve3 runs a local zone** (`America/New_York`, EDT -0400). A UTC host clock is NOT required (the robust escape from the PAN-OS/SRX naive-local-time trap); only NTP accuracy matters.
- VRL: `[transforms.proxmox_sec]` filter (parse_syslog + app-gate + known-pattern gate) → `[transforms.proxmox_ecs]` remap. Branches: sshd `Accepted`/`Failed password` → `auth_*` (source_ip+port); pvedaemon pam `successful auth`/`authentication failure; rhost=` → `auth_*`; `starting|end task UPID:…:<dtype>:<vmid>:<user>:` → `configuration`/`task_<dtype>`/`task_end_<dtype>` (UPID-parsed task_type+vmid+user). `observer_hostname` stays EMPTY (it is the P0/H2 firewall-provenance field; pve3 is not a firewall) — node name + all Proxmox detail ride the `ext` Map (keys `proxmox.node/upid/vmid/task_type/task_status/realm/appname/invalid_user`). Auth-success user is wrapped in single quotes ⇒ extracted via `split()` (VRL on ct102 accepts only `r'...'` literals, which cannot contain a single quote).
- nftables ct102 ingest allow-list: UDP/517 source must be **198.51.100.201** (pve3's LAN IP toward ct102). Apply with `./scripts/apply_ct102_nftables.sh` (rule file `infra/firewall/ct102-ingest.nft`). Runbook (real captured samples in §3/§4): `onboarding/proxmox/rsyslog.md` (notes rsyslog needs installing on a stock PVE host).
- **Live-found appname realities (caught only on the wire, not by `vector test`):** (1) OpenSSH 9.8+/Debian 13 logs per-connection auth under **`sshd-session`** not `sshd` — the gate matches the whole `sshd*` family (an exact `== "sshd"` silently drops ALL SSH auth); (2) CLI/API admin tasks (`pct`/`qm`/`pvesh`) log their task UPID lines under **their own appname, NOT `pvedaemon`** — on this SSH/CLI/MCP-driven host those are the bulk of the admin-action surface, so the app-gate includes them (`is_sec` still restricts them to task lines); web-UI tasks still arrive under `pvedaemon`/`pveproxy`. (3) A failed SSH login emits a redundant sshd `pam_unix(...): authentication failure; logname=… rhost=…` line that surfaced as `unknown` — the auth-failure gate is anchored to `authentication failure; rhost=` (pvedaemon format) so the pam line drops (the companion `Failed password for` line carries the auth_failure). All three pinned by regression tests.
- **Live trigger:** a failed SSH login (use an askpass helper to send a wrong password — a no-password attempt logs `Failed none`, which the `Failed password for` regex won't match) + a normal successful login; for a `task_*` row trigger via the **API path** (`pvesh create /nodes/pve3/lxc/<scratch>/snapshot …` then delete) — a direct CLI `pct snapshot` runs in-foreground and does NOT emit the `starting task UPID` syslog line. Use a SCRATCH VMID only (never the protected list in `~/.claude/CLAUDE.md`). Events land in ~5-10s.

### M12 (MCP ergonomics & agent-routing — ssdf-mcp-query sovereign tools)
- Targeted ergonomics pass on the **sovereign** MCP tool surface to fix routable misses from the 2026-06-15 claude sovereign eval (15/22→16/22). Read-only, additive, no schema change. Branch `m12-mcp-ergonomics`; spec `docs/superpowers/specs/2026-06-18-ssdf-m12-mcp-ergonomics-design.md`, plan `…-mcp-ergonomics.md`. DEPLOYED + live-proven on ct106 2026-06-19.
- Unit tests: `cd services/mcp-query && uv run pytest -m "not integration"` (237 pass — adds nodes_by_attr/observers/observed_by/configured_policies suites); evals: `cd services/evals && uv run pytest -m "not integration"` (64 pass).
- **Two new sovereign tools** (both classed NON-shareable in `classification.py` ⇒ never registered on the public tier): `configured_policies(firewall)` returns the deduped configured-rule count (`count(DISTINCT entity_id)` over `ssdf.entities` ReplacingMergeTree, `kind='policy' AND source='configured'` filtered by `identifiers['provider']`/`['device_name']`) — `firewall_config` class; `observed_by(identifier[, since_hours])` returns which firewall(s) *logged* a given endpoint's flows (L3 provenance via `observer_hostname`→`access_tools._short_host`) — `security_log` class.
- **`topology_snapshot(role=…, kind=…)` filter** (additive): when role/kind set, selects nodes **directly** from `{schema}.graph_nodes FINAL` via `build_nodes_by_attr_sql`/`nodes_by_attr` (current-state inventory, NO time window), then restricts edges to surviving nodes. MUST bypass `load_subgraph` — it derives nodes FROM edges, so isolated firewall `device_inventory` nodes (0 edges) are invisible to it (live-found, masked by unit stubs).
- **Live-found deploy fixes (caught only post-deploy):** (1) `observed_by` `TYPE_MISMATCH` — `ssdf.events.timestamp` is `DateTime64(3,'UTC')` and rejects a raw ISO `+00:00` String cast ⇒ the window bound is wrapped `parseDateTimeBestEffort({since:String})` in `build_observers_for_ips_sql`. (NB: `alerts_for_pair`'s raw `{since:String}` is the same latent pattern — not yet tripped because its callers pass a compatible form.) (2) the `topology_snapshot` isolated-node bug above.
- **Live dependency — panosvm (Proxmox guest 908 `3rdparty-fw`, renumbered from 900 on 2026-08-12):** paloalto ingest (and therefore `observed_by` for panosvm-side IPs + any panos-based eval question) goes stale whenever the panosvm VM is **stopped**. It was found stopped mid-eval; operator restart resumed ingest within ~minutes. guest 908 is on the `~/.claude/CLAUDE.md` NEVER-TOUCH list — flag to the operator rather than starting/stopping it.
- **Corpus follow-through (`services/evals`):** `configured_policies`+`observed_by` added to `corpus.py` `SOVEREIGN_TOOLS`; `golden/core.yaml` re-points `topo-locate-labgen` to `observed_by` (short-label reference SQL) and `reach-configured-policy-count-panosvm` `required_tools` to `[configured_policies]` (its predicate already matched; only the tool-check needed updating once the model correctly routed to the new tool). `topo-firewall-inventory` expectation was `[panosvm, vSRX-test10]` at M12 (only those two were then onboarded); **superseded by M14** — the full fleet is now onboarded and the corpus expectation is the whole role-named fleet (`panosvm` + `vsrx-br01..br12`, `vsrx-campus-a/b`, `vsrx-ci`, `vsrx-core-a/b`, `vsrx-dc`, `vsrx-dmz`, `vsrx-isp-a/b`, `vsrx-prod`, `vsrx-wan-edge`). See `docs/naming-standard.md`.
- Deploy = sync `services/mcp-query/src` to ct106 `/opt/src/mcp-query/src` + `systemctl restart ssdf-mcp-query.service` (editable install). Backup before: ct106 `/root/m12-backup-*`.

### M7c (public de-identified metrics tier — services/public-metrics + metric MCP tools)
- Replaces M7b's anonymized topology graph on the public tier with a keyed-pseudonymized
  metrics/time-series surface for predictive analysis. Public tier now exposes ONLY 3
  metrics tools (`metric_timeseries`, `top_series`, `entity_metric_timeseries`); the 5 M7b
  topology/identity tools are dropped via the phase-0 classification lockdown.
- **Resolver (4th ct109 role):** `services/public-metrics` (venv `/opt/ssdf-public-metrics`,
  env `/etc/ssdf-public-metrics/ENV.local` mode 600) on a ~5-min `ssdf-public-metrics.timer`
  oneshot; writes CH ct104 as `ssdf_pubmetrics` into `ssdf_public.metric_timeseries` (aggregate)
  + `ssdf_public.entity_series` (per-surrogate, top-N) and the sovereign `ssdf.pseudonym_map`.
- Unit tests: `cd services/public-metrics && uv run pytest -m "not integration"`; live:
  `CH_HOST=… CH_PORT=8443 CH_SECURE=1 CH_CA_FILE=… CH_PASSWORD=<pubmetrics_pw>
  CH_PUBLIC_PASSWORD=<public_pw> PUBLIC_PSEUDONYM_KEY=<hex> uv run pytest -m integration`.
- Apply migration: `PUBMETRICS_PW=<pw> envsubst < infra/clickhouse/013_public_metrics.sql |
  clickhouse-client --host <ct104> --multiquery`.
- **Measure catalog (`measures.py`, declarative + extensible):** Tier-1 volume (`bytes`/`flows`/
  `connections`, all enabled — every measure emits the aggregate `metric_timeseries` series;
  only `bytes` ALSO emits a top-N per-surrogate `entity_series` breakdown), Tier-2 normalized
  stance indices (`deny_rate_index`/`ips_volume_index` = ratio-to-baseline, NO absolute counts),
  Tier-3 health placeholders (`mem_util_pct`/`cpu_util_pct`/`iface_error_rate`/`port_flap_count`/
  `proto_flap_count`) DISABLED until M13. Events read with `parseDateTimeBestEffort({since:String})`
  (the M12 DateTime64 cast trap).
- **Pseudonymization:** Python stdlib HMAC-SHA256 (no SipHash-keyed primitive in stdlib),
  per-kind prefix (host=`h_`), 10-hex surrogate, lengthen-on-collision. Key held ONLY on ct109
  via systemd `LoadCredential` (`PUBLIC_PSEUDONYM_KEY_FILE=%d/pseudonym_key`); `config.py` also
  accepts the raw hex `PUBLIC_PSEUDONYM_KEY`. Runbook: `onboarding/public-metrics/key-management.md`.
- **Hard floor:** `ssdf_public` granted SELECT on the 2 metric tables ONLY; `ssdf.pseudonym_map`
  granted to `ssdf_ro` (sovereign `reidentify`) + `ssdf_pubmetrics` (writer), NEVER `ssdf_public`.
- **Tools:** the 3 read tools are classed `metrics` (new configurable class) ⇒ public candidates;
  `reidentify` is classed `identity` and wired sovereign-only. Public lockdown config:
  `services/mcp-query/infra/classification.public.metrics.example.json` (`topology`+`identity`
  back to sovereign, `metrics` shareable).
- **M13 (planned):** operational-health telemetry ingest (mem/CPU util %, iface error-rate,
  flap) — the measure catalog is built extensible so M13 health signals slot in as the
  enabled Tier-3 measures with no redesign.

### M13a (host resource-pressure ingest — services/health → ssdf.health_metrics)
- SSDF's first **operational-health** source: host/device CPU%/mem% + multi-sensor
  temperature across Proxmox (node+guests), vSRX/Junos, PAN-OS, UniFi — all via existing
  vendor MCP op-commands (NO SNMP, no device-side log enablement). A 5th ct109 poller role.
- Unit tests: `cd services/health && uv run pytest -m "not integration"`; live:
  `CH_HOST=… CH_PORT=8443 CH_SECURE=1 CH_CA_FILE=… CH_USER=ssdf_health CH_PASSWORD=<pw>
  JUNOS_MCP_URL=… JUNOS_MCP_TOKEN=… JUNOS_DEVICES=vsrx-br05 PANOS_MCP_URL=… PANOS_MCP_TOKEN=…
  PROXMOX_MCP_URL=… UNIFI_MCP_URL=… UNIFI_DEVICE_MACS=… uv run pytest -m integration`.
- One pass: `cd services/health && uv run python -m ssdf_health.collect_main`.
- Apply migrations: `HEALTH_TTL_DAYS=30 envsubst < infra/clickhouse/014_health_metrics.sql
  | clickhouse-client --host <ct104> --multiquery`; `HEALTH_PW=<pw> envsubst <
  infra/clickhouse/015_health_user.sql | clickhouse-client --multiquery`.
- **Storage:** new EAV-style table `ssdf.health_metrics` (one row per device/metric/sensor/
  timestamp) — `metric_class` (cpu|memory|temperature) + `sensor` are the two discovery
  axes, so a new sensor lands as new rows with NO schema change. Typed `metric_value Float64`
  (NOT the ext Map) so M7c's catalog can aggregate it. TTL 30d default (`HEALTH_TTL_DAYS`).
- **Collectors (`services/health`, mirrors services/topo):** `Gauge` normalized unit; thin
  per-vendor modules (proxmox/junos/panos/unifi) each return `list[Gauge]`; `run_collectors`
  catches+skips a failing collector (one flaky MCP can't zero the pass). Device names match
  topo/policy so a future health↔topology join bridges by name.
- **Per-vendor paths:** Proxmox `get_node_status`/`get_vms`/`get_containers` (cpu fraction →
  %); Junos `show chassis routing-engine` (mem %, cpu=100−idle) + `show chassis environment`
  (per-sensor temps); PAN-OS `<show><system><resources>` (top idle/MiB Mem) +
  `<environmentals>` (thermal entries); UniFi `get_device_by_mac` `system-stats.cpu/.mem` +
  `temperatures[]` (the legacy stat path — integration `get_device_statistics` returns null).
- **Sovereign-only:** queryable immediately via the generic `run_sql`/`describe_schema`
  tools (M11 precedent — no new MCP tool). Public de-id exposure + flipping the M7c
  `mem_util_pct`/`cpu_util_pct` placeholders + the `honesty-device-metrics` eval update are
  deliberate follow-ons (NOT M13a). **Live dependency:** panosvm (guest 908) stopped ⇒ panos
  health rows go stale (flag the operator; do not start/stop it).
- Deploy: rsync `services/health` to ct109 venv `/opt/ssdf-health`, env
  `/etc/ssdf-health/ENV.local` (mode 600), install `ssdf-health.{service,timer}`, enable timer.

### M14 (full-fleet telemetry + role-based naming)
- **Fleet role-rename (M14a):** 23 logical vSRX firewalls renamed to role-based `vsrx-<role>` (all-lowercase kebab) across Proxmox VM names, Junos on-box host-names, rust-junosmcp `devices.json` keys, and SSDF (`JUNOS_DEVICES` ×3, Vector observer gate, eval corpus, docs). Standard: `docs/naming-standard.md`. panosvm unchanged. Vector observer gate dual-accepts old+new names during ~30-day transition (`graph_nodes` + `events` both TTL 30d), then legacy alternates pruned (Phase 1D follow-up).
- **Hotfix (M14):** dual-accept observer gate (fixes 514k/wk unattributed mnha-router + ISP-A/B) broadened to `^vsrx-(test\d|isp-[ab]|mnha-router|production|br\d\d)` (case-preserved for provenance bridge). nftables source range 198.51.100.219-.245. Policy+health collectors expanded from 1-2 devices to full fleet (JUNOS_DEVICES 24 fleet + panosvm).
- **Parser completeness (M14b):** `srx_ecs` RT_SCREEN typed parse (`event_kind=alert`, `category [network,intrusion_detection]`, `action screen_<attack>`) + generic RT_* msgid fallback (never 'unknown' for parseable sd-syslog). `panos_ecs` generic fallback for URL/WILDFIRE/DATA/TUNNEL/AUTH/DECRYPTION. Live invariant: juniper unknown=0.
- **Junos SYSTEM syslog source (M14c):** new Vector source `junos_sys_syslog` UDP/518 + `junos_sys_sec` filter + `junos_sys_ecs` remap (`parse_syslog` RFC5424; auth_* from SSHD_LOGIN_*/Accepted, configuration_* from UI_COMMIT/UI_CFG_AUDIT_*). `event_provider=juniper`, observer gate identical to srx_ecs. nftables UDP/518. Runbook `onboarding/srx/system-syslog.md`. Fleet-wide device config: `set system syslog host 198.51.100.150 port 518 any info structured-data routing-instance mgmt_junos` — **routing-instance REQUIRED** (live-found; without it, syslog fails silently). Live-found: Vector `parse_syslog` nests RFC5424 SD under SD-ID key → SD-ID-agnostic regex extraction.
- **`ingest_status` sovereign tool (M14d):** per-firewall liveness (fresh/stale) with expected set = union of M4 topology firewall nodes + 7d `observer_hostnames`, so a device that stopped entirely still shows (stale, last_event null). Classed `security_log`, never public. Also scoped public-metrics volume measures + `deny_rate_index` to `event_action LIKE 'flow_%'` (was counting auth/config as flows). Live-found: clickhouse-connect returns tz-aware datetimes → hours_since computed in SQL.
- **`fabric_status` sovereign tool:** whole-fabric liveness — every ingest source (juniper/paloalto/proxmox/unifi) and every resolver (topo/entity/policy/health/public-metrics) against a declared budget in `fabric_manifest.py`. Complements `ingest_status`, which stays the per-device firewall view. Two rules encode the 2026-08-19 outage: a subject never observed is `stale`, not absent (UniFi was silent 30+ days and nothing noticed); and a probe that errors is reported in the payload, never swallowed. `ts_column` must be WRITE time — `metric_timeseries.bucket_start` lags ~0.5h by design and would report a healthy resolver stale.
- Run Vector unit tests: on ct102, `vector test /etc/vector/vector.toml` (50/50 incl. M14b+M14c suites). Validate: `CH_HOST=127.0.0.1 vector validate --no-environment infra/vector/vector.toml`.

### M15 (ssdf-common shared library)
- New `services/common` package (`ssdf_common`: mcp_client, clickhouse client_kwargs, config ConfigError/McpEndpoint/load_mcp_endpoint/env_bool, collectors registry+run_collectors). 7 services migrated via thin re-export shims (zero behavior change, 538/538 tests: mcp-query 271, topo 66, entity 64, policy 41, public-metrics 69, health 27, evals 0).
- Installed editable on ct109 (5 services) + ct106 + ct113: `pip install -e /opt/src/common --no-deps`. Each service venv needs it alongside the service itself; a fresh deploy adds the editable install step.
- No code change to services — each reuses its shim `config.py`/`collectors/` (re-exports from `ssdf_common`). Cross-service helpers now centralized; future shared patterns land in `ssdf_common` (no per-service duplication).

### M17 (audit-chain checkpoints + long-retention evidence tier)
- Unit tests: `cd services/mcp-query && uv run pytest -m "not integration"` (adds checkpoint/verify/evidence-archive/orchestrator suites).
- Apply checkpoints schema + user: `: "${CH_CHECKPOINT_PASSWORD:?}" && CHECKPOINT_PW="$CH_CHECKPOINT_PASSWORD" envsubst < infra/clickhouse/022_audit_checkpoints.sql | clickhouse-client --host <ct104> --multiquery` (creates `ssdf.audit_checkpoints` + `ssdf_checkpoint`; grants `ssdf_audit_verify` read access).
- Apply evidence tier schema + user: `: "${CH_ARCHIVER_PASSWORD:?}" && ARCHIVER_PW="$CH_ARCHIVER_PASSWORD" envsubst < infra/clickhouse/023_audit_evidence.sql | clickhouse-client --host <ct104> --multiquery` (creates `ssdf.audit_evidence` + `ssdf_archiver`; grants `ssdf_audit_verify`/`ssdf_checkpoint` read access). Must run after 022.
- Apply OCSF export view + users: `: "${CH_OCSF_DEFINER_PASSWORD:?}" "${CH_AUDIT_EXPORT_PASSWORD:?}" && OCSF_DEFINER_PW="$CH_OCSF_DEFINER_PASSWORD" AUDIT_EXPORT_PW="$CH_AUDIT_EXPORT_PASSWORD" envsubst < infra/clickhouse/024_audit_ocsf_export.sql | clickhouse-client --host <ct104> --multiquery` (creates `ssdf.audit_ocsf_export`, `ssdf_audit_ocsf_definer`, `ssdf_audit_export`). Must run after 023. All four passwords are required — an unset/empty one aborts the apply rather than silently creating a passworded-by-empty-string user.
- Apply events OCSF export view + users: `: "${CH_OCSF_DEFINER_PASSWORD:?}" "${CH_EVENTS_EXPORT_PW:?}" && OCSF_DEFINER_PW="$CH_OCSF_DEFINER_PASSWORD" EVENTS_EXPORT_PW="$CH_EVENTS_EXPORT_PASSWORD" envsubst < infra/clickhouse/026_events_ocsf_export.sql | clickhouse-client --host <ct104> --multiquery` (creates `ssdf.events_ocsf_export`, `ssdf_events_ocsf_definer`, `ssdf_events_export`). Must run after 001 (events). All passwords are required — an unset/empty one aborts the apply rather than silently creating a passworded-by-empty-string user.
- Apply events OCSF authentication export view + users: `: "${CH_OCSF_DEFINER_PASSWORD:?}" "${CH_EVENTS_EXPORT_PW:?}" && OCSF_DEFINER_PW="$CH_OCSF_DEFINER_PASSWORD" EVENTS_EXPORT_PW="$CH_EVENTS_EXPORT_PASSWORD" envsubst < infra/clickhouse/027_events_ocsf_authentication.sql | clickhouse-client --host <ct104> --multiquery` (creates `ssdf.events_ocsf_authentication_export`, `ssdf_events_ocsf_definer`, `ssdf_events_export`). Must run after 026. All passwords are required — an unset/empty one aborts the apply rather than silently creating a passworded-by-empty-string user.
- Run `scripts/checkpoint_audit.py` and `scripts/archive_audit.py` on a schedule (e.g. daily, via the deploy's scheduler of choice); neither schedules itself.

Future Rust/Python components will record their own commands here as they are scaffolded.

## Related external systems

- This operator already runs a live Junos MCP server (`rust-junosmcp`, see the global
  `~/.claude/CLAUDE.md`). It is a reference implementation for the Rust + MCP pattern this
  project follows, and a likely first product-control integration target.
