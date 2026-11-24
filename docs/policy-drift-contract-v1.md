# ssdf.policy_drift Contract v1.0

**Status:** Pinned. **Issue:** ssdf#104. **Migration:** `infra/clickhouse/029_policy_drift.sql`.

Policy-drift verdicts live in their own table, not in `ssdf.audit`, for the
reasons in the [evidence contract](audit-evidence-contract-v1.md) ("Scope"): a
separate TTL and a separate chain. Each row is one check of one intent commit
against one flow or isolation requirement, made by a writer such as mecintent.

## Columns

| Column | Type | Meaning |
|--------|------|---------|
| `ts` | DateTime64(3,'UTC') | Observation time, millisecond precision |
| `server_id` | String | Writer identity; one hash chain per `server_id` |
| `intent_commit` | String | Intent revision checked, e.g. `0123abc` |
| `flow_or_isolation_id` | String | The flow or isolation requirement checked |
| `verdict` | LowCardinality(String) | One of the verdict set below |
| `device` | String | Device the observation came from, e.g. `fw1.example.com` |
| `device_rule_ids` | Array(String) | Device rules involved; may be empty |
| `evidence_ref` | String | Pointer to the supporting evidence |
| `labmode` | UInt8 | `1` when the observation came from a lab-mode MCP, else `0` |
| `prev_hash` | String | `row_hash` of the previous row in this `server_id` chain; `""` at genesis |
| `row_hash` | String | Hash of this row, below |

**Verdicts:** `consistent`, `violating`, `over_permissive`, `unverifiable`.
The issue's "over-permissive" is stored with an underscore. Any other value is
rejected by the writer helper and flagged `invalid_verdict` by the verifier.

`labmode` means the observation was produced by a lab-mode MCP server. It is
part of the hash, so a lab observation cannot be relabelled as production.

## Canonical form and hash

The canonical form is a compact JSON array of the non-hash fields in this
order, with no whitespace (`separators=(",",":")`) and UTF-8 emitted as-is
(`ensure_ascii=False`), so non-ASCII is written literally and `"` and newline
inside a field are escaped as JSON does:

```
[ts, server_id, intent_commit, flow_or_isolation_id, verdict, device,
 device_rule_ids, evidence_ref, labmode]
```

- `ts` is UTC ISO-8601 truncated (not rounded) to milliseconds:
  `2026-11-24T10:00:00.123Z`.
- `device_rule_ids` is a JSON array, `[]` when empty.
- `labmode` is the integer `0` or `1`.

```
row_hash = lowercase_hex( SHA-256( prev_hash + "\n" + canonical(row) ) )     (UTF-8)
```

`prev_hash` is `""` for a chain's genesis row, so the hashed string starts with
the newline. `row_hash` carries no `sha256:` prefix. Known-answer vectors,
computed with `jq` and `sha256sum` rather than this repository's code, are in
`services/mcp-query/tests/fixtures/drift_chain_vectors.json`
(`scripts/gen_drift_vectors.sh` regenerates them). They cover non-ASCII, a
`"` and a newline in a field, and an empty `device_rule_ids`.

## Seeding protocol

Chains are per `server_id`. A writer must continue its own chain across
restarts, and must not start a second root:

1. Read the head for its `server_id` as `ssdf_audit_verify` (the head is the
   row whose `row_hash` no other row in that `server_id` names as `prev_hash`).
   A failed read is not "nothing landed"; stop rather than insert blind.
2. If there is no row, start at genesis: `prev_hash = ""`.
3. Otherwise set `prev_hash` to the head's `row_hash`, compute the new
   `row_hash`, and insert as `ssdf_drift`.
4. A replay of a row that already landed is skipped by re-reading the head.

**Retries and the dedup token.** The table sets
`non_replicated_deduplication_window = 10000`. The head read cannot cover an
insert whose outcome was never learned (a timeout), so every insert carries
`insert_deduplication_token`, and a retry resends the same block with the same
token, which the database drops:

```
token = len(utf8(server_id)) ":" server_id ":" len(utf8(run_id)) ":" run_id ":" segment_seq
```

`run_id` identifies the writer's run and `segment_seq` is the 0-based block
counter within it. Lengths are **UTF-8 byte** counts, not code points, and
the prefix is required: joining on `:` alone is not injective (`("a:b","c",1)`
and `("a","b:c",1)` would collide, and the database would drop a real row while
the writer is told it succeeded). The implementation is
`ssdf_mcp_query.audit_chain.dedup_token`, re-exported by `drift_chain`; the
same vectors that pin the evidence token apply (see `test_verify_audit.py`).

## Access

| Identity | Rights |
|----------|--------|
| `ssdf_drift` | INSERT only. Cannot read back or change a verdict it wrote |
| `ssdf_audit_verify` | SELECT, for the head read and the verifier |
| `ssdf_ro` | none; `run_sql` refuses the table |

mecintent is a writer. Reading drift through MCP is the sovereign-only
`policy_drift` tool (data class `firewall_config`); it is absent on the public
tier. The sovereign tier requires `local_only` tokens (contract section 8). A
remote token can be scoped with `allowed_tools=["policy_drift"]`, but
`local_only` is an attestation, not locality: it states where the token is
meant to be used and does not enforce it.

## Retention, TTL and `anchored`

Rows expire after **410 days** (`TTL toDateTime(ts) + INTERVAL 410 DAY`),
covering a 13-month audit. Expiry removes the oldest rows first, so a chain
whose genesis has aged out starts with a row whose `prev_hash` names a row that
no longer exists.

The verifier reports that chain as **`anchored: false`**, and it is not an
issue: the chain is intact from its earliest surviving row, but it can no
longer be shown to start at genesis. `anchored: true` means the earliest row has
`prev_hash == ""`. The root and head are derived from the links, not from `ts`,
so tied timestamps do not matter.

**Known limit (Decision 3).** Deleting a chain's genesis row is
indistinguishable from TTL age-out: both leave an unknown `prev_hash` on the
root and both read `anchored: false`. Telling them apart needs signed
checkpoints of the chain head, which do not exist yet and are deferred to a
follow-up. Until then `anchored: false` is a statement about what survives,
not proof that nothing was removed from the front.

## Verifier issue vocabulary

`python -m ssdf_mcp_query.verify_drift` (reads as `ssdf_audit_verify`). Each
issue is `{type, server_id, row_hash}`:

| Type | Meaning |
|------|---------|
| `content_edit` | Recomputing the hash from the row and its `prev_hash` does not give the stored `row_hash` |
| `missing_predecessor` | `prev_hash` names a row that does not exist, or belongs to another `server_id`; tolerated only on the chain root, where it means `anchored: false` |
| `duplicate_row` | The same `row_hash` is stored more than once |
| `fork` | Two rows in one chain share a `prev_hash` |
| `invalid_verdict` | `verdict` is outside the verdict set |

A row from writer B never links into writer A's chain: a `prev_hash` that is
another writer's hash is always `missing_predecessor`.

## Round-trip script

`scripts/verify_drift_contract.py` exercises the protocol end to end against a
scratch ClickHouse: head read, insert, skipped replay, tokened duplicate
dropped, read-back, inline chain check. **It writes to the table** and refuses
any non-loopback host. The throwaway-container recipe is the `sql-contract` job
in `.github/workflows/ci.yml`.

## Version History

- **v1.0** (2026-11-24): Initial contract (ssdf#104).
