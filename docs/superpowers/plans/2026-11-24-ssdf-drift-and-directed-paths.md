# SSDF policy-drift table (#104) and directed L3 paths (#103) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give mecintent a hash-chained policy-drift table readable over the sovereign MCP tier (Part A), and route-table-derived directed paths with on-path enforcement points and per-hop zones (Part B).

**Architecture:** Part A adds one new ClickHouse table, `ssdf.policy_drift`, with its own chain, written by mecintent directly into ClickHouse (as `mecmcp-audit` does for evidence), verified by a new offline verifier, read by one new sovereign-only MCP tool. Part B collects route/interface/zone facts from Junos and PAN-OS through the vendor MCP servers into two new tables, and answers path queries with a pure LPM engine that pulls routes per hop (it never builds a graph of prefixes). It returns `undetermined` instead of a guess.

**Tech Stack:** Python 3.12, uv (one `uv.lock` per service), ClickHouse 24.8, FastMCP, pytest, ruff 0.12.4.

**Spec:** `mecintent: docs/topology-contract.md` (§2 -> #103, §6 truncation/scale, §7 -> #104, §8 access). Issues: mechubsec/ssdf #104, #103.

## Decisions needed (answer before Task A2 / B-tasks marked)

1. **Drift writer path (blocks A1, A2).** Recommended: mecintent inserts directly into ClickHouse as a new INSERT-only user `ssdf_drift`, exactly as `mecmcp-audit` does for `ssdf.audit`. It matches SSDF's "MCP tools are read-only" rule and needs no new write surface. The alternative is an MCP write tool, which would add the first write tool, a new token scope and an audited write path. This plan assumes direct insert.
2. **Drift read identity (A2, A4).** Recommended: grant `SELECT ON ssdf.policy_drift` to the existing `ssdf_audit_verify` and use it for both the verifier and the MCP tool, so no new config secret is needed. The alternative is a new `ssdf_drift_read` user plus a new `Config` secret. `ssdf_ro` must NOT be granted, and `sql_guard` must refuse the table either way.
3. **TTL (A2).** The issue requires at least 90 days. Recommended: 410 days, matching `ssdf.audit_evidence` (023). Chain checkpoints for drift are deferred, so the verifier anchors at the oldest surviving row and reports `anchored: false`. Confirm that deferral. If you want signed checkpoints and archival (022/023 equivalents), that is a follow-up issue of about the same size as Part A.
4. **Data class for the drift tool (A4).** Recommended: reuse `firewall_config`, since drift exposes device rule ids and policy revisions. It is not a new class, because `DATA_CLASSES` is a closed set of five. The drift tool is sovereign-only and absent from the public tier.
5. **Contract-vs-code on `find_path` (B6).** The contract says `find_path(src, dst, direction)`, but `find_path` is registered on the PUBLIC tier too. The public edge view has no `attrs`, and routes are sovereign data. Recommended: a new sovereign-only tool `forwarding_paths(src, dst, direction)`, with legacy `find_path` unchanged (its docstring says "undirected, not forwarding"). Then update the contract wording in mecintent. Alternative: break `find_path`'s return shape, which breaks public callers.
6. **Lab config change for ECMP/failover captures (B1).** The real-bytes requirement for ECMP and failover needs a lab vSRX with two equal-cost static routes and a floating backup. That is a config change on a lab device through the MCP change-set flow. It is a separate operator-approved step, lab-mode only, and not on any `protected` guest. Without it the ECMP/backup parsers are covered only by real single-path bytes plus hand-built multi-path text, which this repo's own lessons call insufficient. Approve it or accept the gap.
7. **`direction` semantics and result status (B5/B6).** Recommended: `direction in {"forward","reverse","both"}` (forward = src to dst; reverse = dst to src; both = return both walks). Status values: `determined` (every branch delivered), `partial` (some branches delivered, others failed with reasons), `undetermined` (none delivered). Confirm `partial` is acceptable under the contract's "MUST say so explicitly".
8. **Failover representation (B5).** Recommended: paths from active routes are `role:"primary"` (ECMP = several primaries); paths from inactive, same-prefix backup routes are `role:"backup"`. We do not model BGP/OSPF convergence.
9. **IPv4 only in v1 (B2-B6).** The capture and parsers cover `inet` only; IPv6 is a follow-up. The engine uses `ipaddress`, so it is v6-ready. Confirm.
10. **UniFi gateway routes are out of scope** (not verified to be reachable via `unifi_*` tools).
11. **mecintent writer language.** Recommended: Rust, which must reproduce the canonical hash byte-for-byte. The A1 vectors are the cross-language gate, so hand them to the mecintent owner.

## Global Constraints

- CI per service: `cd services/<svc> && uv run pytest -m "not integration" -q`. Lint: `uvx ruff@0.12.4 check services` and `uvx ruff@0.12.4 format --check services`. No per-file ignores.
- Markers: `integration` (live lab, `CONFIRM_LAB_INTEGRATION=yes`, via `just integration`) and `contract` (throwaway ClickHouse). The `sql-contract` CI job in `.github/workflows/ci.yml` lists its test files explicitly, so every new `contract` test file MUST be added to that line.
- Migrations: `infra/clickhouse/NNN_*.sql`, next free numbers are **029** (drift) and **030** (routes). `scripts/run_migrations.py` refuses duplicate prefixes. User-creating migrations use `${X_PW}` placeholders; do not commit real values. `scripts/apply_contract_schema.py` `MIGRATIONS` takes plain-DDL files only (no `CREATE USER`).
- SSDF never writes config to devices. Collectors call read-only vendor MCP tools only.
- Every MCP tool must appear in `classification.py` `TOOL_DATA_CLASSES` and `ssdf_evals.corpus.SOVEREIGN_TOOLS` (`services/evals/tests/test_registry_drift.py` guards both).
- Test vectors for parsers are real captured device bytes, not hand-written. Hash vectors are computed with `sha256sum`/`jq`, never with this repo's Python.
- Each task is one reviewable commit (<~400 lines excluding fixtures). Commit trailer: `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`. Run the Codex review gate (`codex-review-gate` skill) per commit. Do not push main directly.
- Branch from `origin/main`: one branch per part (`feat/104-policy-drift`, `feat/103-directed-paths`). One agent per working directory.

## Review Focus

- Chain boundary and TTL: a drift chain whose genesis has aged out must verify as `anchored:false`, not fail or pass silently (A3).
- Two writers interleaved: chains are per `server_id`, and a row from writer B must not link into writer A's chain (A3).
- Hash canonicalisation edge cases: non-ASCII, `"` and `\n` inside `device`, and an empty `device_rule_ids` array (A1).
- Duplicate insert (retry): the same dedup token must collapse to one row, and a same-content replay must not look like tampering (A2 contract test, A3).
- Drift readable by `run_sql` or the public tier (must be refused/absent) (A4).
- Overlapping prefixes and a default route: LPM must pick the longest prefix, not the first or the lowest metric (B5).
- Routing loop, or next-hop owned by no collected device: return `undetermined` with a reason, never the shortest undirected path (B5, B6).
- Same prefix in two routing instances/VRs: no cross-contamination (B5).
- Firewall hop with an interface that has no zone mapping: report `zone: null` with a flag, do not omit the hop (B5).
- Truncation: a tool that hits the node cap or the route-row cap reports it (B6, B7).

---

# Part A: #104 policy-drift record (ships first)

### Task A1: Canonical hash module and independent test vectors

**Files:**
- Create: `services/mcp-query/src/ssdf_mcp_query/drift_chain.py`
- Create: `services/mcp-query/tests/fixtures/drift_chain_vectors.json`
- Create: `scripts/gen_drift_vectors.sh` (documents how the vectors were produced; uses `jq` and `sha256sum` only)
- Test: `services/mcp-query/tests/test_drift_chain.py`

**Interfaces:**
- Produces: `VERDICTS: frozenset[str]` = `{"consistent","violating","over_permissive","unverifiable"}`. Note the underscore: the issue's "over-permissive" is stored as `over_permissive`; the contract doc says so.
- Produces: `canonical(row: dict) -> str`. Row keys: `ts` (datetime), `server_id`, `intent_commit`, `flow_or_isolation_id`, `verdict`, `device`, `device_rule_ids` (list[str]), `evidence_ref`, `labmode` (bool or int). Output is `json.dumps([ts_ms_iso(ts), server_id, intent_commit, flow_or_isolation_id, verdict, device, list(device_rule_ids), evidence_ref, int(labmode)], separators=(",",":"), ensure_ascii=False)`. It raises `ValueError` on a verdict outside `VERDICTS`.
- Produces: `compute_row_hash(prev_hash: str, row: dict) -> str` = `sha256(prev + "\n" + canonical(row))` hex. It reuses `audit_chain.ts_ms_iso`. Genesis `prev_hash` is `""`.
- Produces: `dedup_token(server_id: str, run_id: str, segment_seq: int) -> str` by import-reuse of `audit_chain.dedup_token`. Do not re-implement it.

- [ ] **Step 1: Generate vectors independently.** Write `scripts/gen_drift_vectors.sh`. For each of 4 hand-chosen rows, build the canonical JSON array with `jq -cn --arg ... '[...]'` and chain with `printf '%s\n%s' "$prev" "$canon" | sha256sum`. `jq -c` with `--arg` emits UTF-8 unescaped, matching `ensure_ascii=False`. Rows: (a) genesis, ASCII, `labmode=1`; (b) second row linking to (a); (c) `device` = `fw-é"x\ny`, covering non-ASCII, quote and newline; (d) `device_rule_ids=[]`, `labmode=0`, `verdict=over_permissive`. Run it and write the output to `drift_chain_vectors.json` as `[{"row":{...,"ts":"2026-11-24T10:00:00.123Z"},"prev_hash":"...","canonical":"...","row_hash":"..."}]`. The commit message states the vectors came from jq/sha256sum.
- [ ] **Step 2: Write the failing tests** in `test_drift_chain.py`:
  - `test_vectors_reproduce` loads the JSON and asserts `canonical(row) == v["canonical"]` and `compute_row_hash(v["prev_hash"], row) == v["row_hash"]` for each.
  - `test_chain_links`: vector b's `prev_hash` equals vector a's `row_hash`.
  - `test_unknown_verdict_rejected` -> `ValueError`.
  - `test_ts_truncates_to_ms`: `ts` with microseconds 123999 gives `...123Z`.
  - `test_any_field_change_changes_hash`: parametrised over all 9 fields.
- [ ] **Step 3: Run** `cd services/mcp-query && uv run pytest tests/test_drift_chain.py -q`. Expected: FAIL (module missing).
- [ ] **Step 4: Implement** `drift_chain.py` per the Interfaces above (pure, no I/O, docstrings on public functions).
- [ ] **Step 5: Sabotage check.** Temporarily change the separator in `compute_row_hash` from `"\n"` to `"\r\n"`. The vector test must fail. Revert and re-run until green. Note this in the commit body.
- [ ] **Step 6: Run** the pytest and ruff commands above. Expected: PASS.
- [ ] **Step 7: Commit** `feat(drift): canonical row hash and independent vectors (#104)`.

### Task A2: Migration 029, users, grants, contract-schema wiring

**Files:**
- Create: `infra/clickhouse/029_policy_drift.sql`
- Modify: `infra/clickhouse/README.md` (migration list), `scripts/apply_contract_schema.py` (`MIGRATIONS`: the table DDL must be plain, so put `CREATE USER`/`GRANT` in 029 and the table in the same file only if the script's `statements()` filter can skip them; otherwise split the table DDL to `029_policy_drift.sql` and the users to `029b`-style handling noted below), `.github/workflows/ci.yml` (sql-contract test list)
- Modify: `services/mcp-query/src/ssdf_mcp_query/sql_guard.py` (add `"policy_drift"` to the refused-table set beside `audit`)
- Test: `services/mcp-query/tests/test_policy_drift_migration.py` (text, pattern of `test_audit_evidence_migration.py`), `services/mcp-query/tests/test_policy_drift_contract.py` (`@pytest.mark.contract`)

**Interfaces:**
- Produces table `ssdf.policy_drift`: `ts DateTime64(3,'UTC')`, `server_id String`, `intent_commit String`, `flow_or_isolation_id String`, `verdict LowCardinality(String)`, `device String`, `device_rule_ids Array(String)`, `evidence_ref String`, `labmode UInt8`, `prev_hash String`, `row_hash String`. Engine `MergeTree ORDER BY (server_id, ts)`, `TTL toDateTime(ts) + INTERVAL 410 DAY` (value per Decision 3), and the same `non_replicated_deduplication_window` setting that 016 applies to `ssdf.audit`. Read 016 and copy its form and window rationale.
- Produces users: `ssdf_drift` (INSERT-only, no SELECT, `${DRIFT_PW}`), plus `GRANT SELECT ON ssdf.policy_drift TO ssdf_audit_verify` (Decision 2). No grant to `ssdf_ro`.
- Consumes: migration runner conventions in `scripts/run_migrations.py` (`${VAR}` envsubst, fail closed).

- [ ] **Step 1: Write failing text tests:** table is created; TTL regex `INTERVAL (\d+) DAY` is >= 90 (assert >= 410 per decision); both hash columns present; `GRANT INSERT ON ssdf.policy_drift TO ssdf_drift` and no SELECT for it; no `TO ssdf_ro`; no `ALTER`/`DELETE`; the dedup setting is present; `sql_guard` refuses `policy_drift` (parametrise over the existing refusal test helper).
- [ ] **Step 2: Run** `uv run pytest tests/test_policy_drift_migration.py -q`. Expected: FAIL.
- [ ] **Step 3: Write 029** (header comment in the style of 009/023: envsubst usage, the insert-only rationale, "no backfill").
- [ ] **Step 4: Wire the contract schema.** Check how `apply_contract_schema.py` `statements()` handles `CREATE USER`. If user DDL cannot run unauthenticated in the throwaway CH, put the table DDL in `029_policy_drift.sql` and the users in a following file, `infra/clickhouse/029_policy_drift_users.sql`... but the runner refuses duplicate numeric prefixes, so take 030 for users and shift Part B's route migration to 031. Record whichever you choose in the commit body. Add the table migration to `MIGRATIONS`.
- [ ] **Step 5: Write the contract test** (`contract` marker). It applies the schema, inserts two chained rows with vector rows from A1 using `insert_deduplication_token`, re-inserts the same block with the same token and asserts `count() == 2`, then selects them back ordered by ts.
- [ ] **Step 6: Add the new contract test file to the `sql-contract` pytest line in `ci.yml`.**
- [ ] **Step 7: Run** the text tests, then the contract test against a local `clickhouse/clickhouse-server:24.8-alpine` (`docker run` as CI does), the full `mcp-query` suite and ruff. Expected: PASS.
- [ ] **Step 8: Commit** `feat(drift): ssdf.policy_drift table, insert-only writer, TTL (#104)`.

### Task A3: Chain verifier

**Files:**
- Create: `services/mcp-query/src/ssdf_mcp_query/verify_drift.py`
- Test: `services/mcp-query/tests/test_verify_drift.py`

**Interfaces:**
- Consumes: `drift_chain.compute_row_hash`; the issue-dict style of `verify_audit.verify_tier_detailed` (read it and reuse the issue type names `hash_mismatch`, `broken_link`, `fork`, `duplicate`, `unreachable` where they apply, so operators see one vocabulary).
- Produces: `verify_chains(rows: list[dict]) -> dict` returning `{"chains": {server_id: {"rows": n, "head": hash, "anchored": bool}}, "issues": [{"type":..., "server_id":..., "row_hash":...}], "ok": bool}`. A chain is anchored only if its first row has `prev_hash == ""`. A dangling first `prev_hash` (the genesis expired by TTL) is NOT an issue: it gives `anchored:false`. A gap inside the chain is a `broken_link` issue.
- Produces: `fetch_rows(config) -> list[dict]` (reads `ssdf.policy_drift ORDER BY ts` as `ssdf_audit_verify`, as `verify_audit._make_client`/`_fetch_rows` do) and `main(argv)` with `python -m ssdf_mcp_query.verify_drift` printing the summary and exiting non-zero on issues.

- [ ] **Step 1: Write failing tests**, building rows with `compute_row_hash`: clean 3-row chain is ok and anchored; mutated `verdict` gives `hash_mismatch`; a deleted middle row gives `broken_link`; two rows with the same `prev_hash` gives `fork`; an identical row replayed gives `duplicate`; two interleaved `server_id`s each verify independently and a cross-linked row is flagged; a chain whose first row has a non-empty unknown `prev_hash` is `ok` with `anchored:false`; a bad verdict value is an issue.
- [ ] **Step 2: Run** `uv run pytest tests/test_verify_drift.py -q`. Expected: FAIL.
- [ ] **Step 3: Implement** `verify_chains` (group by `server_id` column, no JSON parsing), `fetch_rows`, `main`. The verifier recomputes every row (unlike evidence, the drift hash is ours to define).
- [ ] **Step 4: Sabotage each detection separately** (the cargo-style "one fix at a time" lesson applies here too). Disable `fork` detection, run, and confirm only the fork test fails. Restore it. Repeat for `broken_link` and `hash_mismatch`.
- [ ] **Step 5: Run** the pytest and ruff commands. Expected: PASS.
- [ ] **Step 6: Commit** `feat(drift): offline chain verifier (#104)`.

### Task A4: Sovereign read tool, classification, evals corpus

**Files:**
- Create: `services/mcp-query/src/ssdf_mcp_query/drift_tools.py`
- Modify: `services/mcp-query/src/ssdf_mcp_query/server.py` (register in the sovereign-only block near `raw_tools["explain_access"]`, L440; not in the shared dict that the public tier gets), `services/mcp-query/src/ssdf_mcp_query/classification.py` (`TOOL_DATA_CLASSES["policy_drift"] = frozenset({"firewall_config"})`), `services/evals/src/ssdf_evals/corpus.py` (`SOVEREIGN_TOOLS` += `policy_drift`, plus 2 corpus questions copying the shape of an existing sovereign entry, e.g. "which flows are currently violating policy?" requiring `policy_drift`)
- Test: `services/mcp-query/tests/test_drift_tools.py`, extend `services/mcp-query/tests/test_server_sovereignty.py` / `test_classification.py` (pattern only), `services/evals/tests/test_registry_drift.py` must pass unmodified

**Interfaces:**
- Produces: `build_drift_sql(verdict: str | None, flow_or_isolation_id: str | None, device: str | None, intent_commit: str | None, since_hours: int, limit: int) -> tuple[str, dict]`. It uses `{name:Type}` parameters, never string interpolation; `limit` is capped at 500; verdict is validated against `drift_chain.VERDICTS`.
- Produces: `DriftTools(client).policy_drift(verdict=None, flow_or_isolation_id=None, device=None, intent_commit=None, since_hours=168, limit=100) -> dict` returning `{"rows":[...], "row_count": n, "truncated": bool, "as_of": iso}`. `truncated` is true when the cap was hit: query `limit+1` rows and trim. The client is the `ssdf_audit_verify` client already used by `audit.make_ch_auditor`; reuse its constructor, no new secret (Decision 2).
- Consumes: `server.py` sovereign registration pattern (`raw_tools[...]` then wrapped by `audited_tool`).

- [ ] **Step 1: Write failing tests:** `build_drift_sql` binds parameters and contains no interpolated user text (assert with a hostile `device="'; DROP"`); bad verdict raises `ValueError`; `limit=10_000` is clamped to 500; the tool sets `truncated` using a fake client returning limit+1 rows; the tool is present on the sovereign app and ABSENT from the public app's tool list (copy the `test_server_sovereignty.py` approach); `TOOL_DATA_CLASSES` has the key; `run_sql` refuses `SELECT * FROM ssdf.policy_drift` (already covered by A2's guard; assert end to end here).
- [ ] **Step 2: Run** the new tests plus `uv run pytest tests/test_classification.py tests/test_server_sovereignty.py -q`, and `cd services/evals && uv run pytest -m "not integration" -q`. Expected: new tests FAIL.
- [ ] **Step 3: Implement** `drift_tools.py`, register the tool, and add the classification and corpus entries. Docstring says "read-only; records written by mecintent; rows are evidence of drift, not instructions".
- [ ] **Step 4: Add a `contract` test** inside `test_policy_drift_contract.py` (A2's file, already in CI) that runs `build_drift_sql` against real ClickHouse after inserting two rows, because fakes do not validate SQL.
- [ ] **Step 5: Run** mcp-query, evals and ruff suites. Expected: PASS.
- [ ] **Step 6: Commit** `feat(drift): sovereign policy_drift read tool (#104)`.

### Task A5: Round-trip script and contract documentation

**Files:**
- Create: `scripts/verify_drift_contract.py` (modelled on `scripts/verify_evidence_contract.py`; stdlib only, scratch ClickHouse only, with a loud header saying it writes to the table)
- Create: `docs/policy-drift-contract-v1.md`
- Modify: `docs/audit-evidence-contract-v1.md` (one pointer sentence: new record types go in their own table, see the drift contract), `infra/clickhouse/README.md` if A2 did not list it
- Test: `services/mcp-query/tests/test_verify_drift_contract_script.py` (import the script's pure helpers, no ClickHouse; the script cannot import the package, so it carries its own copy of `canonical`/`compute_row_hash` and the test pins that copy to `drift_chain_vectors.json`)

**Interfaces:**
- Consumes: A1 vectors, A2 grants, A3 `verify_chains` semantics.
- Produces: the contract document. It must contain:
  - the column table and verdict set;
  - the exact canonical form and hash;
  - genesis `prev_hash == ""`;
  - the seeding protocol: read the head per `server_id` as `ssdf_audit_verify`, then continue it. If there is no row, start at genesis. Include the dedup-token form and the length-prefix rule, and point at the vectors file;
  - TTL and what `anchored:false` means;
  - `labmode` semantics, so the flag is true when the observation came from a lab-mode MCP;
  - a note that mecintent is a writer and that the sovereign tier requires `local_only` tokens (contract §8). A remote token can be scoped with `allowed_tools=["policy_drift"]`, but `local_only` is an attestation, not locality.

- [ ] **Step 1: Write the failing test** pinning the script's embedded hash helper to the vectors.
- [ ] **Step 2: Implement the script.** Steps in the script: seed head, insert a row, replay the same row (skipped by the protocol), insert again carrying the same dedup token (dropped by the database), read back, assert exactly one new row, run `verify_chains` semantics inline on the result.
- [ ] **Step 3: Write the contract doc**, then run the script once against a scratch ClickHouse (docker, not the lab) and paste the one-line summary into the PR.
- [ ] **Step 4: Run** the test and ruff. Expected: PASS.
- [ ] **Step 5: Commit** `docs(drift): contract v1 and round-trip script (#104)`. Open the PR for Part A; `Closes #104`.

---

# Part B: #103 directed L3 paths (starts after Part A merges; B1 can start in parallel because it needs no code)

### Task B1: Capture real route/interface/zone bytes (operator-approved steps, no code)

**Files:**
- Create: `services/topo/tests/fixtures/junos_route_active.txt`, `junos_route_all.txt`, `junos_interfaces_terse.txt`, `junos_security_zones.txt`, `junos_route_instance.txt`, `panos_routing_route.json`, `panos_interface_all.json`, plus `services/topo/tests/fixtures/README-captures.md` listing for each file the MCP server, device name, command, date, and Junos/PAN-OS version.

**Interfaces:** none (feeds B2/B3).

This is an operator-approved sequence. Do not run any step until the operator says go for that step, and run reads only unless stated. Use the lab-mode servers (`prod-labmode-junos`, `prod-labmode-panos`), never a `protected` guest and never `prod-junos2mcp`/`prod-panos2mcp` for devices the lab-mode catalogue does not list.

- [ ] **Step 1: Pick devices.** `get_router_list` / `list_devices` on the lab-mode servers; choose one lab vSRX and one lab PAN-OS. Record names. Query Proxmox tags first (`protected` guests are off limits).
- [ ] **Step 2 (approval gate): Junos reads** via `execute_junos_command`: `show route table all active-path` (and the same without `active-path` so inactive/backup routes appear), `show interfaces terse`, `show security zones`, `show route instance` (instance-to-interface membership). Save raw returned text byte-for-byte into the fixtures.
- [ ] **Step 3 (approval gate): PAN-OS reads** via `execute_panos_op`: `<show><routing><route/></routing></show>` and `<show><interface>all</interface></show>`. Save the raw envelope, including the `max_bytes` truncation field.
- [ ] **Step 4 (approval gate, mutating, Decision 6): ECMP and backup.** If approved, add two equal-cost static routes and one floating backup on the lab vSRX through the MCP change-set flow (`create_junos_change_set` -> approve -> apply), re-capture `show route table all` (ECMP shows several next-hops under one prefix; backup shows an inactive entry), then remove the change through the same flow and confirm the config is back to baseline with `junos_config_diff`.
- [ ] **Step 5: Inspect** the bytes before any parser work. Write down in `README-captures.md`: how ECMP and inactive routes appear, how routing-instance headers appear, whether output is paginated or truncated, and whether the Junos MCP returns bare text or an envelope. This decides the parser shape in B2 and B3, and is why captures come first.
- [ ] **Step 6: Check fixtures contain no credentials** (`gitleaks detect --no-git --source services/topo/tests/fixtures`) and commit them without editing the bytes. If redaction is unavoidable, diff the removed lines rather than grepping for tokens.
- [ ] **Step 7: Commit** `test(topo): captured route/interface/zone fixtures (#103)`.

### Task B2: Junos route/interface/zone collector

**Files:**
- Modify: `services/topo/src/ssdf_topo/collectors/junos.py` (new parsers and three more entries in the best-effort command loop, L160-185)
- Test: `services/topo/tests/test_collector_junos.py` (extend)

**Interfaces:**
- Produces new `Observation.observation_type` values (all `layer="l3"`, `source_device` = router name):
  - `route_entry`: `subj_kind="device"`, `subj_id=f"device:{dev}"`, attrs `instance`, `prefix`, `next_hop` ("" for connected/receive), `out_interface`, `protocol`, `preference`, `metric`, `active` ("1"/"0"). One observation per next-hop, so ECMP is N rows with the same prefix.
  - `interface_addr`: attrs `instance`, `interface`, `address` (IP), `prefixlen`.
  - `interface_zone`: attrs `interface`, `zone`.
- Produces: `parse_routes(text: str, source_device: str, now: str) -> list[Observation]`, `parse_interfaces_terse(...)`, `parse_security_zones(...)`, `parse_route_instances(...)`, with the same signatures as the existing `parse_arp`.
- Consumes: B1 fixtures. The parsers must handle only the shapes in the real bytes (instance header lines, `*[Static/5]` active markers, `>` and ECMP continuation lines) and skip unknown lines without raising.

- [ ] **Step 1: Write failing tests** from fixtures: expected counts and one fully asserted `route_entry` per kind (static, direct, local, ECMP with 2 next-hops, inactive backup); a prefix present in two instances keeps `instance` distinct; empty and garbage input gives `[]`; interface `ge-0/0/1.0` with `inet 10.0.1.1/24` gives `interface_addr`; zone membership parsed from `show security zones`.
- [ ] **Step 2: Run** `cd services/topo && uv run pytest tests/test_collector_junos.py -q`. Expected: FAIL.
- [ ] **Step 3: Implement the parsers** and add the commands to `JunosCollector.collect` inside the existing per-command try/except (one failure must not drop the device).
- [ ] **Step 4: Add a collector-level test** with a fake client that returns fixture text per command and one command raising, asserting the other observations still arrive.
- [ ] **Step 5: Run** the `services/topo` suite and ruff. Expected: PASS.
- [ ] **Step 6: Commit** `feat(topo): junos route, interface and zone observations (#103)`.

### Task B3: PAN-OS route/interface/zone collector

**Files:**
- Modify: `services/topo/src/ssdf_topo/collectors/panos.py`
- Test: `services/topo/tests/test_collector_panos.py` (extend)

**Interfaces:**
- Produces: `parse_routes_xml(text, source_device, now)` and `parse_interfaces_xml(text, source_device, now)` emitting the same three observation types as B2 (`instance` = virtual-router name, `zone` from the interface entry).
- Consumes: B1 PAN-OS fixtures; the existing `_entries`, `_f`, `envelope_truncated` helpers and the truncation rule in `PanosCollector.collect` (a truncated payload is dropped, never half-parsed, and a route table is exactly the thing that must not be partially reported).

- [ ] **Step 1: Write failing tests** from fixtures: static, connected and ECMP-flagged routes; interface zone mapping; a truncated envelope yields no route observations and a logged warning (assert with `caplog`); malformed XML returns `[]`.
- [ ] **Step 2: Run** `uv run pytest tests/test_collector_panos.py -q`. Expected: FAIL.
- [ ] **Step 3: Implement** the two parsers and add both commands to the `PanosCollector.collect` loop.
- [ ] **Step 4: Run** the topo suite and ruff. Expected: PASS.
- [ ] **Step 5: Commit** `feat(topo): panos route, interface and zone observations (#103)`.

### Task B4: Route and interface store, resolver output, migration 030

**Files:**
- Create: `infra/clickhouse/030_device_routes.sql` (use 031 if A2 consumed 030)
- Modify: `services/topo/src/ssdf_topo/resolver/resolve.py` (emit `routes_to` edges), `services/topo/src/ssdf_topo/chwriter.py` (write the two new tables), `services/topo/src/ssdf_topo/collect_resolve.py` (wire), `scripts/apply_contract_schema.py` (`MIGRATIONS`), `.github/workflows/ci.yml` (new contract file), `infra/clickhouse/README.md`
- Test: `services/topo/tests/test_resolve.py` (extend), `services/topo/tests/test_chwriter.py` (extend), `services/mcp-query/tests/test_device_routes_migration.py`, contract test `services/mcp-query/tests/test_device_routes_contract.py`

**Interfaces:**
- Produces table `ssdf.device_routes` (`ReplacingMergeTree(last_seen)`, `ORDER BY (tenant_id, device, instance, prefix, next_hop, out_interface)`, 30-day TTL like `graph_*`): `tenant_id`, `device`, `instance`, `prefix String` (CIDR text), `next_hop String`, `out_interface String`, `protocol LowCardinality(String)`, `preference UInt32`, `metric UInt32`, `active UInt8`, `last_seen DateTime64(3,'UTC')`.
- Produces table `ssdf.device_interfaces` (`ReplacingMergeTree(last_seen)`, `ORDER BY (tenant_id, device, instance, name)`): `tenant_id`, `device`, `instance`, `name`, `addr_ips Array(String)`, `addrs Array(String)` (CIDR), `zone String`, `role LowCardinality(String)` (copied from device inventory, `firewall` or empty), `last_seen`. Add a skip index on `addr_ips` (bloom_filter) for owner lookups.
- Produces: `routes_to` edges in `resolve_graph`: one per (source device, next-hop-owner device) with `layer="l3"`, attrs `instances` and `prefix_count`. The route tables hold the truth; edges are a navigational summary (edge ids are keyed by (src,dst,type,layer) so per-prefix edges would collapse). The next-hop owner is resolved via the `interface_addr` observations. Unresolvable next-hops produce no edge.
- Grants: `ssdf_topo` INSERT on both tables; `ssdf_ro` SELECT on both (018 pattern). No public view (routes are sovereign data), and add both tables to `sql_guard`'s refused set so `run_sql` cannot read them.

- [ ] **Step 1: Write failing tests:** migration text (both tables, grants, TTL, no public grant); `resolve_graph` turns B2/B3-shaped observations into the expected `routes_to` edge and ignores unowned next-hops; the chwriter test uses the existing fake-client pattern and asserts the column order of inserted rows.
- [ ] **Step 2: Run** `cd services/topo && uv run pytest -q` and the mcp-query migration test. Expected: FAIL.
- [ ] **Step 3: Write the migration, writer and resolver changes.** `route_entry`/`interface_addr`/`interface_zone` observations are folded into table rows by the writer. The resolver stays pure.
- [ ] **Step 4: Contract test** (`contract` marker, added to the `sql-contract` line): insert rows for two instances and an ECMP prefix, read back with `FINAL`, assert replacement semantics (re-insert with a newer `last_seen` leaves one row).
- [ ] **Step 5: Run** the topo, mcp-query and ruff suites, plus the contract test against local ClickHouse. Expected: PASS.
- [ ] **Step 6: Commit** `feat(topo): device_routes/device_interfaces store and routes_to edges (#103)`.

### Task B5: Pure path engine

**Files:**
- Create: `services/mcp-query/src/ssdf_mcp_query/path_engine.py`
- Test: `services/mcp-query/tests/test_path_engine.py`

**Interfaces:**
- Produces dataclasses (frozen): `Route(device, instance, prefix, next_hop, out_interface, protocol, preference, metric, active)`, `Iface(device, instance, name, addrs: tuple[str, ...], zone: str | None, role: str)`, `Hop(device, instance, role, ingress_interface, ingress_zone, egress_interface, egress_zone)`, `PathResult(status, paths, undetermined)`. Each path is `{"role": "primary"|"backup", "hops": [Hop...], "delivered_on": (device, interface)}`. `undetermined` is a list of `{"reason", "at_device", "detail"}`.
- Produces `class FabricSource(Protocol)`: `routes_for(device: str, instance: str, dst_ip: str) -> list[Route]` (routes whose prefix contains `dst_ip`, active and inactive), `iface_owning_ip(ip: str) -> Iface | None`, `iface_in_subnet(ip: str) -> Iface | None` (first-hop discovery), `iface(device, instance, name) -> Iface | None`.
- Produces `trace(source: FabricSource, src_ip: str, dst_ip: str, max_hops: int = 32, max_paths: int = 64) -> PathResult`.
- Reasons (a closed `Literal`): `no_first_hop`, `no_route`, `next_hop_unowned`, `loop`, `max_hops`, `max_paths`, `uncollected_device`.

Algorithm (state it in the module docstring, one line each): start at the interface whose connected subnet contains `src_ip`. At each device/instance, take routes containing `dst_ip`, pick the longest prefix, then among that prefix's routes the active ones are primary (all next-hops, giving ECMP) and the inactive ones are backup. A route with an empty `next_hop` (connected) delivers on `out_interface`. Otherwise resolve `next_hop` to its owning interface and continue from there as ingress. Track a visited set of (device, instance, ingress) per branch for loop detection. Delivery is a connected route toward `dst_ip`, or `dst_ip` owned by the current device's interface. There is NO fallback to graph shortest path.

- [ ] **Step 1: Write failing tests with an in-memory `FabricSource`** (all as `def test_...` with expected `PathResult` fields): single path A to fw to B with ingress/egress zones at the firewall; ECMP gives 2 primary paths; floating static gives 1 primary plus 1 backup; overlapping /8, /16, /24 picks /24 (and a /0 default is used only when nothing longer matches); same prefix in two instances stays separate; loop returns `undetermined` reason `loop`; next-hop owned by nobody returns `next_hop_unowned` (and NOT a path); no first hop returns `no_first_hop`; firewall interface with `zone=None` yields `ingress_zone: None` and the hop is still present; `max_paths` cap returns the cap reason; mixed delivered/failed branches gives status `partial`; only failures gives `undetermined`; a non-firewall transit device appears in `hops` but not in the enforcement list helper below.
- [ ] **Step 2: Run** `uv run pytest tests/test_path_engine.py -q`. Expected: FAIL.
- [ ] **Step 3: Implement** `trace` and `enforcement_hops(result) -> list[Hop]` (hops where `role == "firewall"`, de-duplicated per path). No ClickHouse, no networkx.
- [ ] **Step 4: Sabotage:** change LPM to "first match" and confirm the overlapping-prefix test fails; remove the visited-set and confirm the loop test fails (bounded by `max_hops`, with a different reason, so assert the exact reason). Restore.
- [ ] **Step 5: Run** the mcp-query suite and ruff. Expected: PASS.
- [ ] **Step 6: Commit** `feat(paths): pure LPM/ECMP path engine with explicit undetermined (#103)`.

### Task B6: ClickHouse fabric source and `forwarding_paths` MCP tool

**Files:**
- Create: `services/mcp-query/src/ssdf_mcp_query/route_store.py` (ClickHouse-backed `FabricSource`), `services/mcp-query/src/ssdf_mcp_query/forwarding_tools.py`
- Modify: `server.py` (sovereign-only registration beside `policy_drift`), `classification.py` (`"forwarding_paths": frozenset({"topology","firewall_config"})`), `services/evals/src/ssdf_evals/corpus.py` (`SOVEREIGN_TOOLS` plus 2 questions), `topo_tools.py` (`find_path` docstring "undirected L1/L2/L3 reachability, not forwarding; use forwarding_paths", and the legacy filter excluding `routes_to` edges so its results do not change)
- Test: `services/mcp-query/tests/test_route_store.py`, `test_forwarding_tools.py`, extend `test_topo_tools.py`; `contract` test appended to `test_device_routes_contract.py`

**Interfaces:**
- Produces: `build_routes_sql(tenant: str, device: str, instance: str, dst_ip: str, row_cap: int) -> tuple[str, dict]` using `isIPAddressInRange({dst:String}, prefix)` and `FINAL`, `LIMIT row_cap+1`; `build_owner_sql(tenant, ip)`; `build_subnet_sql(tenant, ip)`.
- Produces: `class ClickHouseFabric(FabricSource)` that counts rows and exposes `.truncated: bool`. It is set when any lookup hit the cap. Reads are per hop, never a whole-table load.
- Produces: `ForwardingTools(store, fabric_factory).forwarding_paths(src: str, dst: str, direction: str = "forward") -> dict`. Resolve `src`/`dst` with `store.find_node` to IPs (`identifiers.ip`, or a literal IP), validate `direction`, run `trace` once or twice, and return `{"status","direction","paths":[...],"enforcement_points":[...],"undetermined":[...],"truncated": bool,"as_of": iso}`. An unknown entity returns `{"error":"not_found"}`. A malformed `direction` returns an error and never raises.

- [ ] **Step 1: Write failing tests:** SQL builders are parameterised (hostile `device`); the fake-ClickHouse fabric reads route fixtures and returns `Route`s; `forwarding_paths` for `both` returns two result blocks; `truncated` is true when the row cap is hit; sovereign-only registration (absent from the public app); `TOOL_DATA_CLASSES` entry; `find_path` returns exactly the same dict as before for a graph containing a `routes_to` edge.
- [ ] **Step 2: Run** `uv run pytest tests/test_route_store.py tests/test_forwarding_tools.py tests/test_topo_tools.py -q`. Expected: FAIL.
- [ ] **Step 3: Implement**; `fabric_factory` builds a fresh `ClickHouseFabric` per call so `.truncated` is per request. Add the evals corpus entries.
- [ ] **Step 4: Contract test** against real ClickHouse: seed a small three-router lab (fw between two subnets, one ECMP prefix) via the migration's tables, run `forwarding_paths`, and assert primaries, zones and `delivered_on`. This is the only test that validates the SQL.
- [ ] **Step 5: Live check (marker `integration`, operator-approved):** after the topo timer has collected the lab vSRX (B2) run `forwarding_paths` between two lab hosts behind it and compare the hops with `show route <dst>` on the device. Record the comparison in the PR. A parser fix is not accepted on a green suite alone.
- [ ] **Step 6: Run** mcp-query, evals suites and ruff. Expected: PASS.
- [ ] **Step 7: Commit** `feat(paths): forwarding_paths tool with on-path enforcement points (#103)`.

### Task B7: Truncation flags, scale note, contract wording

**Files:**
- Modify: `services/mcp-query/src/ssdf_mcp_query/topo_tools.py` (add `truncated` and `as_of` to `find_path`, `enforcement_points`, `neighbors`, `locate` responses, derived from `len(nodes) >= MAX_NODES` in `_build`), `docs/data-model.md` (a short "Routes and forwarding" section), `services/mcp-query/tests/test_topo_tools.py`
- Create: `docs/scale-4000-devices.md` (one page)

**Interfaces:**
- Consumes: `_build` returns `(graph, node_by_id, edges)`; extend it to also return `truncated: bool` without changing existing call signatures used by other tests (add a `self._last_truncated` is NOT acceptable under concurrency; return it explicitly and update the four callers).
- Produces: the same `truncated: bool` and `as_of: str` keys on those tool results. Paging remains contract §6's separate item; this task only covers truncation reporting.

- [ ] **Step 1: Write failing tests:** each of the four tools returns `truncated: True` when the fake store returns `MAX_NODES` nodes and `False` otherwise; `as_of` is ISO UTC.
- [ ] **Step 2: Run** `uv run pytest tests/test_topo_tools.py -q`. Expected: FAIL.
- [ ] **Step 3: Implement** the change.
- [ ] **Step 4: Write the scale note** (facts only): at 4,000 devices plus hosts, `MAX_NODES = 5000` is exceeded, so `_build`-based tools (`find_path`, `enforcement_points`, `neighbors`, `locate`) truncate. `forwarding_paths` is unaffected because it does per-hop indexed lookups (`ORDER BY (tenant_id, device, instance, ...)`), roughly hops times 3 queries per path. Estimated rows: devices x routes per device, with the 30-day `ReplacingMergeTree`. State the measured numbers from the lab once B6's live check runs, and say "not measured" where it was not. Paging (§6) and snapshot ids stay open in separate issues.
- [ ] **Step 5: Run** the mcp-query suite and ruff. Expected: PASS.
- [ ] **Step 6: Commit** `feat(topo-tools): report truncation and as_of on graph tools; scale note (#103)`. Open the Part B PR; `Closes #103`; ask mecintent's owner to update `topology-contract.md` §2 for the `forwarding_paths` name (Decision 5).

---

## Self-review notes

- Spec coverage: §7 drift record (A1-A5), own chain per writer (A1/A3), insert-only and TTL (A2), sovereign read (A4), contract/round-trip (A5), CI list (A2/B4). §2: routes per device and instance (B2-B4), LPM and all paths (B5), enforcement points with ingress/egress zone (B5/B6), explicit undetermined (B5/B6). §6 truncation (B7), scale note (B7). §8 access documented (A5), no new code.
- Known soft spots: A2 step 4 (contract-schema vs `CREATE USER`) depends on how `apply_contract_schema.statements()` treats user DDL and may shift the route migration to 031. B2/B3 parser shapes are deliberately unspecified until B1 bytes exist. Part B's later tasks should be re-checked against those captures.
