# ssdf.audit Evidence Contract v1.0

**Version:** 1.0
**Date:** 2026-08-09
**Status:** Active
**SSDF Compatibility:** Requires schema 009 (hash chain support)

## Purpose

This contract defines the ingestion schema for firewall configuration-change evidence records written by mecmcp-audit (the rustsdcmcp audit sink) into ssdf.audit. It extends the existing MCP tool-call audit trail to carry a complete evidence chain for each configuration change: proposal, approval, apply intent, and result receipt.

## Schema Ownership

- **Table:** `ssdf.audit` (existing, created by migration 007, hash-chained by 009)
- **Write Identity:** `ssdf_audit` (INSERT-only, no SELECT — deliberately; see
  [ingestion](./audit-evidence-ingestion.md) for how dedup works without it)
- **Verify Identity:** `ssdf_audit_verify` (SELECT-only, hash-chain verification)
- **Schema Steward:** ssdf repo (this contract document)
- **Primary Consumer:** mecmcp-audit (rustsdcmcp audit sink, will implement in Task 7+9)

## Record Types

Evidence records use the existing `ssdf.audit` schema with the following `tool` field values:

| tool | Description | Decision Phase |
|------|-------------|----------------|
| `evidence:proposal` | Configuration change proposed by an agent | Pre-approval |
| `evidence:approval` | Human approval of a proposed change | Approval gate |
| `evidence:apply_intent` | System begins executing the approved change | Execution start |
| `evidence:result_receipt` | Execution result returned from the device | Execution complete |

All evidence records share `tier = "evidence"` to enable chain verification independent of the MCP tool audit trail.

### The chain is per writer, not per tier

**Revised 2026-08-20 (ssdf#47).** A chain is `(tier, server_id)`, and each
writer has exactly **one** root.

Chaining the whole tier would require every writer to serialise against a shared
head, and fifteen MCP servers write `tier = "evidence"` with no such lock. Each
would seed `prev_hash = ""`, the tier would acquire one accepted root per
server, and the verifier — which traverses every root — would report clean.
Worse, with many roots, deleting an **entire run** removes a whole independent
root and leaves nothing unreachable: the one failure this mechanism exists to
catch would be invisible.

Grouped by writer, each server has one root, and a run that continues its
predecessor's head makes a wholesale deletion show up as `missing_predecessor`.

Consequences for a writer:

- Seed a new run from the writer's **current head**, not from `""`. Only a
  genuinely empty `(tier, server_id)` starts at `""`.
- Never run two recorders for one `server_id` concurrently. They would fork the
  chain, and a fork verifies as two valid chains rather than as an error.

Rows carrying no `server_id` — every `sovereign` row — group by tier alone and
verify exactly as before.

## Caller attribution columns (added 2026-08-27, ssdf#9)

`ssdf.audit` carries three further columns, all `String DEFAULT ''` (migration
`017_audit_attribution.sql`):

| Column | Trust | Source |
|---|---|---|
| `client_name` | **client-asserted** | MCP `clientInfo.name` at initialize; a client may claim anything |
| `model_id` | operator-declared | the token entry; requires token-file write access |
| `actor_type` | operator-declared | the token entry; constrained to `human` \| `agent` \| `unknown` |

These are not interchangeable. The trail must not imply it verified something it
cannot, so a reader must treat `client_name` as a claim and the other two as
statements by whoever provisioned the token.

### Effect on the hash chain: none, unless a row uses them

`canonical()` appends these three fields **only when at least one is non-empty**.
So:

- every row written before this migration serialises to the original
  nine-element form and verifies against its stored hash
- every `tier="evidence"` row from `mecmcp-audit`, which does not set these
  columns, does the same

**No coordinated release is required, and no backfill is possible.** A row
written before this migration genuinely had no attribution; inventing one would
be a fabricated audit record.

A producer that *does* populate them must fold them into `row_hash` in this
order — `client_name`, `model_id`, `actor_type`, appended after `error` — or its
rows will not verify. Attribution is inside the tamper-evidence deliberately:
otherwise anyone able to write to the table could reattribute a call to a
different model or actor without breaking the chain, which is exactly the
tampering the chain exists to expose.

Verified end to end on 2026-08-27 against ClickHouse 24.8: a chain mixing
unattributed and attributed rows verifies, and altering `model_id` on a stored
row is detected.

## Scope: this contract covers the change lifecycle only

**Decided 2026-08-20 (ssdf#47, mecmcp#292).** The four record types above are
the complete set. `ssdf.audit` takes **`tier = "evidence"`** from mecmcp and
nothing else.

The question was whether the MCP fleet's per-call stream — reads, denials,
transport events — should also land here under a `tier = "mcp"`. It should not,
for three reasons:

1. **Volume swamps the signal.** One production server emits roughly 30,000
   records in three weeks, almost all reads. Evidence records are a handful per
   change. Mixed in the same table, the chain-verifiable rows become a rounding
   error in something sized and tuned for telemetry.
2. **The retention is wrong for it.** `ssdf.audit` has a 90-day TTL. That is
   generous for telemetry and short for evidence: the record of who approved a
   configuration change should outlive the record of who listed a device. One
   TTL cannot serve both, and raising it to suit evidence means keeping three
   months of reads that nobody wants.
3. **The chain is per-tier.** Adding a high-volume tier to a table whose value
   is a verifiable chain means the verifier walks far more rows to check far
   fewer, and a gap in the noisy tier looks like a gap in the table.

**Where per-call records go instead:** they stay where they already are —
structured JSON in each server's journald, sealed with Forward Secure Sealing,
with stated 90-day retention and device names pseudonymised (`hmac:…`, stable,
so they correlate without exporting the inventory). That trail is already
tamper-evident at rest and does not need this table to become so.

If a per-call tier is ever wanted here, it should be a **separate table** with
its own TTL and its own chain, not a tier in this one.

## Field Schema

Evidence records populate the existing `ssdf.audit` columns as follows:

| Column | Type | Evidence Semantics | Example |
|--------|------|-------------------|---------|
| `ts` | DateTime64(3,'UTC') | Evidence event timestamp (UTC) | `2026-08-09T14:32:10.500Z` |
| `principal` | LowCardinality(String) | Originating agent/user identity | `"agent:mechub-config-agent"` for proposals, `"user:alice@example.com"` for approvals |
| `tier` | LowCardinality(String) | **Always `"evidence"`** for these records | `"evidence"` |
| `tool` | LowCardinality(String) | Evidence record kind (see Record Types) | `"evidence:proposal"` |
| `args` | String | JSON-encoded evidence payload (see Payload Schema) | `{"request_id":"req_abc123",...}` |
| `data_classes` | Array(LowCardinality(String)) | Affected device/changeset classifications | `["device:vsrx-prod","changeset:cs_xyz"]` |
| `decision` | LowCardinality(String) | Approval outcome (`"approved"`, `"rejected"`, `""`) | `"approved"` (approval records only) |
| `row_count` | UInt32 | Devices/rules affected count | `1` |
| `error` | String | Error detail (execution failures only) | `"commit failed: syntax error at line 42"` |
| `prev_hash` | String | Previous row hash in the evidence tier chain | `"sha256:abc123..."` |
| `row_hash` | String | This row's computed hash | `"sha256:def456..."` |

### Payload Schema (`args` column)

The `args` field carries a JSON object with evidence-specific fields:

```json
{
  "request_id": "req_abc123",
  "changeset_id": "cs_xyz789",
  "device_id": "vsrx-prod",
  "diff_hash": "sha256:fedcba...",
  "run_id": "run_20260809_143210",
  "server_id": "rustsdcmcp-606",
  "segment_seq": 0,
  "prev_hash": "sha256:...",
  "approver": "alice@example.com",
  "metadata": {
    "commit_message": "Fix NAT rule typo",
    "change_summary": "Updated rule policy-1 source address"
  }
}
```

| Payload Field | Type | Required | Description |
|--------------|------|----------|-------------|
| `request_id` | string | Yes | Unique change request identifier |
| `changeset_id` | string | Yes | Configuration changeset identifier |
| `device_id` | string | Yes | Target device identifier |
| `diff_hash` | string | Yes | SHA-256 hash of the configuration diff |
| `run_id` | string | Yes | Audit run identifier (for deduplication) |
| `server_id` | string | Yes | Originating audit server identifier |
| `segment_seq` | integer | Yes | Sequence number within this run (0-based) |
| `prev_hash` | string | Conditional | Previous record hash (empty for first record) |
| `approver` | string | Approval only | Approving user identity |
| `metadata` | object | Optional | Additional context (commit message, etc.) |

## Deduplication Contract

Re-ingestion after a demo reset or test re-run MUST be idempotent. The deduplication key is:

```
(server_id, run_id, segment_seq)
```

**Implementation note:** dedup is a **high-water mark read before the insert**,
not a guard on the insert itself. Before replaying, the sink reads the highest
`segment_seq` it already has for `(server_id, run_id)` as `ssdf_audit_verify`
and inserts only what is above it; see
[audit-evidence-ingestion.md](audit-evidence-ingestion.md) for the query and
its `count()`, which is what keeps segment 0 from being skipped.

An earlier version of this note recommended `ReplacingMergeTree` or
`INSERT ... WHERE NOT EXISTS`. Neither is available: `ssdf.audit` is a
`MergeTree`, and the guarded insert needs a `SELECT` that the INSERT-only
`ssdf_audit` identity is specified not to have — verified against the live
table, where it is refused with `Code: 497 ... Not enough privileges`. Every
guarded insert would have been rejected.

### What the high-water mark does not cover

A read-then-insert is not atomic against an insert that is **already in
flight**. If an HTTP INSERT times out while ClickHouse is still committing it,
the sink cannot tell whether the row landed; the high-water read before its
retry can answer "nothing", and the original can then commit alongside the
retry. Two identical rows, in a plain `MergeTree` that will not reject them.

Closing it needs the database, because no ordering of two client-side
statements can be atomic against a request already in flight. Migration
[`016_audit_insert_dedup.sql`](../infra/clickhouse/016_audit_insert_dedup.sql)
enables ClickHouse's own insert deduplication on the table:

```sql
ALTER TABLE ssdf.audit MODIFY SETTING non_replicated_deduplication_window = 10000;
```

and writers send a token identifying the segment:

```
insert_deduplication_token=<len(server_id)>:<server_id>:<len(run_id)>:<run_id>:<segment_seq>
```

for example `9:junos-950:5:run-7:42`. The **byte length of each identifier
precedes it**, and that is not decoration: identifiers are free-form, so
joining on a separator alone is not one-to-one — `("a:b", "c", 1)` and
`("a", "b:c", 1)` both give `a:b:c:1`. Two segments sharing a token is the
worst outcome available here, because ClickHouse acknowledges the insert and
drops the block: a real segment disappears while the writer is told it
succeeded. Lengths make the field boundaries unambiguous.

A retried block carrying a token ClickHouse has already seen is dropped, so the
duplicate never lands. `ssdf.audit` is a plain (non-replicated) `MergeTree` —
verified live — and those have supported this since 22.2; 701 runs 26.6.

Not `ReplacingMergeTree`, which was the first proposal on #49: it rewrites a
live table and pushes `FINAL`/`argMax` semantics onto every reader, where this
changes one setting and leaves reads exactly as they are.

**Until the migration is applied**, the window is open and the mitigation is
detection: `verify_audit.py` counts occurrences of each `row_hash` and reports
`duplicate_row`, because the pair is invisible to every other check — identical
content means an identical hash, so hash-keyed linkage and reachability both
pass. Sending the token before the setting exists is harmless, so writers need
no coordination with the migration.

## Query Contract

The evidence chain for a given `run_id` is queried as:

```sql
SELECT ts, tool, principal, args, row_hash, prev_hash
FROM ssdf.audit
WHERE tier = 'evidence'
  AND JSONExtractString(args, 'run_id') = '<run_id>'
ORDER BY ts ASC
```

This query is consumed by:
- The Task 11 mechub-web evidence viewer
- Hash-chain verification tools
- Audit reports

## Retention

Evidence records follow the existing `ssdf.audit` TTL:
- **90 days** (per migration 007)
- Evidence older than 90 days is automatically purged by ClickHouse

For long-term compliance storage, export evidence rows to cold archive before TTL expiration.

## Authentication

Evidence records are written via the existing `ssdf_audit` identity (INSERT-only, no SELECT). The mecmcp-audit sink authenticates with:

```bash
# Environment variable (per .env.example pattern)
CH_AUDIT_PASSWORD=<from-vault>
```

No new authentication identity is required for this contract — the existing `ssdf_audit` user supports the evidence record shape.

## Hash Chain Integrity

Evidence records participate in a hash chain **per writer**, keyed
`(tier, server_id)` — not one chain per tier (migration 009):

1. **First evidence record of a `server_id`** has `prev_hash = ""` (chain start)
2. **Subsequent records** include `prev_hash = <previous row_hash>`, where
   "previous" means this writer's previous record, across all of its runs
3. **row_hash** is the writer's digest of its full EvidenceRecord: the
   sorted-key canonical JSON of `kind`, `request_id`, `changeset_id`,
   `device_id`, `principal`, `diff_hash`, `timestamp`, `run_id`, `server_id`,
   `segment_seq`, `prev_hash` and, where present, `approver`, `decision`,
   `outcome`, `error` and `metadata`, as `sha256:<hex>`
   (mecmcp-audit `sinks/ssdf.rs` `compute_record_hash`). It includes the
   record's nanosecond `timestamp` and fields that ssdf.audit does not store,
   so **SSDF cannot recompute it**. `verify_audit.py` therefore checks evidence
   rows for linkage, reachability and checkpoint anchoring only, never content,
   and prints `content=writer-hashed(not-recomputed)` for the tier. Content
   integrity for evidence rows rests on the writer's signed segments.

### Why per writer

One chain per tier would require every server writing evidence to agree on a
shared head. They do not: they are separate processes on separate hosts,
inserting concurrently. Their records interleave, so a tier-wide verifier
compares each row's `prev_hash` against a predecessor written by a different
server and every check fails — not because anything was tampered with, but
because it is reading two chains as one.

### Seeding a new run

A writer's second run continues its first run's chain, so on startup it reads
its own head — the `row_hash` of its most recent row — rather than starting a
new root:

```sql
-- as ssdf_audit_verify
SELECT DISTINCT row_hash
FROM ssdf.audit
WHERE tier = 'evidence'
  AND JSONExtractString(args, 'server_id') = {server_id:String}
  AND row_hash NOT IN (
      SELECT prev_hash
      FROM ssdf.audit
      WHERE tier = 'evidence'
        AND JSONExtractString(args, 'server_id') = {server_id:String}
        AND prev_hash != ''
  )
```

The tail is the row **nothing else points at** — it is found by following the
links, not by sorting. Ordering by `ts` and `segment_seq` looks equivalent and
is not: `segment_seq` restarts at 0 for each run, so an older run's segment 40
outranks the real tail's segment 0, and two records sharing a millisecond or a
clock that stepped backwards break the tiebreak as well. A writer seeded from
an interior hash forks its own chain, and a fork verifies as two valid chains.

An empty result means a genuinely new writer, which starts a root.

Note the `DISTINCT`. Two *rows* can share one unreferenced `row_hash` — that is
exactly what an ambiguous-timeout duplicate of the current tail looks like, and
it is one chain head, not two. Comparing row counts would call it a fork and
stall ingestion over a condition that is merely a duplicate, which
`verify_audit.py` already reports as `duplicate_row`.

**More than one _distinct_ hash is the answer to a different question.** A
healthy chain has exactly one unreferenced tail; two distinct ones mean it has
already forked, and a writer that resumes from either deepens the fork. Treat
that as a fault to investigate, not as a tie to break. This is separate from the run-scoped high-water mark in
[audit-evidence-ingestion.md](audit-evidence-ingestion.md), which answers a
different question — what to skip on replay, not where to attach.

**One writer per `server_id`, one run at a time.** Two processes sharing a
`server_id`, or one process running two runs concurrently, both fork the chain,
and a fork verifies as two valid chains rather than as an error — so nothing
downstream will tell you it happened. Give each container its own `server_id`.

The hash chain is verified offline via:

```bash
python -m ssdf_mcp_query.verify_audit
```

This verifier reads as `ssdf_audit_verify` and confirms:
- No missing sequence gaps
- Each `prev_hash` matches the prior row's `row_hash`
- No tampered fields (recomputed hash matches stored hash)

## Version History

- **v1.0** (2026-08-09): Initial contract pin for mechub demo milestone
