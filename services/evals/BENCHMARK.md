# NL→SQL Benchmark (SSDF M8 eval harness)

> a mechub project — natural language to SQL evaluation for network firewall automation agents

## Overview

This package contains the **NL→SQL benchmark corpus and scoring infrastructure** for evaluating LLM tool-calling accuracy on natural language queries against firewall log data. The benchmark tests whether an agent can:

1. Understand natural language questions about firewall traffic
2. Translate them to ClickHouse SQL queries
3. Return structured JSON answers that match ground truth

This is **not** a general-purpose SQL benchmark—it's specifically designed for **SSDF's firewall log analysis domain** (reachable at [SSDF](https://github.com/fastrevmd-lab/ssdf)).

## When to Use This Benchmark

Use this benchmark when you want to evaluate an LLM's ability to:

- Translate natural language to SQL for firewall log analysis
- Route to the correct MCP tools (e.g., `top_talkers`, `explain_access`)
- Return structured JSON answers that match SQL-based ground truth
- Refuse to answer questions it cannot answer (honesty questions)

**This benchmark is NOT suitable for:**

- Evaluating general SQL generation (use HumanEval, Spider, etc.)
- Evaluating network automation tool routing (use [mechubbench](https://github.com/mechubsec/mechubbench))
- Testing ClickHouse performance (use ClickHouse benchmarks)

## Architecture

```
┌─────────────────────────────────────────┐
│      SSDF repo (this repository)        │
├─────────────────────────────────────────┤
│  golden/core.yaml                       │ ← 33 questions (the corpus)
│  schemas/manifest.schema.json           │ ← run contract
│  schemas/scorecard.schema.json          │ ← output format
│  ssdf_evals/                            │
│    ├─ score.py        (scorer CLI)      │
│    ├─ regress.py      (regression gate) │
│    ├─ corpus.py       (load/filter)     │
│    ├─ predicates.py   (scoring logic)   │
│    └─ auditcheck.py   (audit verification) │
└─────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│   External runner repo (not included)   │
│   ┌─────────────────────────────────┐   │
│   │   ssdf-eval-runner/             │   │
│   │     ├─ core.py                  │   │
│   │     ├─ claude_adapter.py        │   │
│   │     ├─ qwen_adapter.py          │   │
│   │     └─ run.py                   │   │
│   └─────────────────────────────────┘   │
└─────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────┐
│         SSDF live clickhouse            │
│         (prod environment)              │
└─────────────────────────────────────────┘
```

**The contract:** The runner executes questions against SSDF's MCP endpoints, records answers, and produces a `manifest.json`. SSDF's scorer reads the manifest, runs reference SQL against ClickHouse, checks tool usage in `ssdf.audit`, and outputs a `scorecard.json`.

## The Corpus

Location: `services/evals/golden/core.yaml`

- **33 questions** across 5 categories:
  - `reachability` (4 questions) - Which rules allowed flows, which firewalls observed traffic
  - `flows` (12 questions) - Top talkers, event counts, vendor distributions
  - `topology` (7 questions) - Which devices are firewalls, path existence, entity identification
  - `change` (6 questions) - Policy names, event dates, freshness checks
  - `honesty` (8 questions) - Refusal questions (no data, can't answer, no permission)

Each question includes:
- `id`: Stable identifier (kebab-case)
- `question`: Natural language query
- `tier`: `sovereign` | `public` | `both`
- `category`: Category label
- `difficulty`: `easy` | `medium` | `hard`
- `answer_format`: Template for required JSON output
- `required_tools`: Tools the agent should route to (if any)
- `predicate`: Ground truth check (SQL, expected JSON, or refusal)

Example:

```yaml
- id: flows-top-talkers-24h
  question: Who were the top 3 talkers (source IPs) by bytes in the last 24 hours?
  tier: sovereign
  category: flows
  difficulty: medium
  answer_format: 'Answer with JSON: {"talkers": [{"ip": "<ip>", "bytes": <int>}, ...]}'
  required_tools: [top_talkers]
  predicate:
    type: reference_sql
    sql: >
      SELECT toString(source_ip) FROM ssdf.events
      WHERE timestamp >= now() - INTERVAL 24 HOUR AND source_ip IS NOT NULL
      GROUP BY source_ip ORDER BY sum(network_bytes) DESC LIMIT 3
    match: set_overlap
    answer_key: talkers
    item_key: ip
    params: {min_overlap: 2}
```

## Running the Benchmark

### Prerequisites

1. **External runner repo**: This codebase does not include the runner. You need a separate repository that:
   - Connects to SSDF's MCP endpoints
   - Executes questions and records answers
   - Produces a manifest JSON

2. **Access credentials**:
   - SSDF MCP endpoint URL
   - Eval principal token (see `services/mcp-query/infra/tokens.README.md`)
   - ClickHouse connection (for scoring)

3. **Python environment** (for scoring only):
   ```bash
   cd services/evals
   uv sync
   ```

### Scoring a Run

After the runner produces a manifest:

```bash
cd services/evals

# Required environment variables
export CH_HOST=<clickhouse-host>
export CH_PORT=8443
export CH_SECURE=1
export CH_CA_FILE=<path-to-ssdf-ca.crt>
export CH_USER=ssdf_ro
export CH_PASSWORD=<ssdf_ro-password>
export CH_AUDIT_VERIFY_PASSWORD=<ssdf_audit_verify-password>

# Score a run
uv run python -m ssdf_evals.score /path/to/manifest.json

# Check for regressions
uv run python -m ssdf_evals.regress results/<scorecard>.json
```

**Exit codes:**
- `0`: Scoring succeeded (scorecard written to `results/`)
- `1`: Regressions detected (listed on stderr)
- `2`: Config/schema/scoring error

### Running Unit Tests

```bash
cd services/evals

# Unit tests (no ClickHouse required)
uv run pytest -m "not integration"

# Corpus lint (schema validation, ID uniqueness, etc.)
uv run pytest -m "corpus_lint"
```

### Verifying the Corpus

Before running a benchmark, verify the corpus is valid:

```bash
cd services/evals

# Lint the corpus (check schema, unique IDs, tier/tool consistency)
uv run pytest -m "corpus_lint" -v

# If you have ClickHouse access, run integration tests
# (note: integration tests require live CH and audit access)
uv run pytest -m integration -v
```

**Expected output**: All lint tests pass (`PASSED`). If a test fails, the error message indicates the corpus issue (e.g., duplicate ID, invalid tier, sovereign-only tool in public question).

## Scoring Details

### Predicate Types

| Type | Description | Match modes |
|------|-------------|-------------|
| `reference_sql` | Evaluate SQL against live ClickHouse | `exact`, `set_overlap`, `numeric_tolerance` |
| `expected_json` | Compare to static expected value | `exact` (default) |
| `refusal` | Agent correctly refuses to answer | N/A |

### Match Modes

- `exact`: Answers must match character-for-character
- `set_overlap`: Answers are sets; pass if overlap >= threshold (params: `min_overlap` or `min_overlap_pct`)
- `numeric_tolerance`: Answers are numbers; pass if within tolerance (params: `tolerance` or `tolerance_pct`)

### Tool Check

For each question, the scorer verifies:
1. All `required_tools` appear in the agent's audit window
2. No sovereign-only tools appear in `tier: public` runs

Audit data is sourced from `ssdf.audit` using the `ssdf_audit_verify` principal and the `manifest.principal` + time window (`started ± slop`, default 5s).

## Why This Belongs in SSDF (Not mechubbench)

### Architecture Comparison

| Feature | SSDF NL→SQL | mechubbench |
|---------|-------------|-------------|
| **Domain** | ClickHouse firewall log queries | Network config tasks |
| **Test target** | SQL translation + tool routing | Tool routing only |
| **Ground truth** | Reference SQL queries | Expected tool calls |
| **Data source** | Live ClickHouse DB | Fixture configs |
| **Use case** | Evaluate SQL generation for network analysis | Evaluate tool calls for config automation |

### Decision Rationale

1. **Domain-specific data**: The NL→SQL benchmark requires access to SSDF's ClickHouse schema, tables, and data. Questions test understanding of SSDF-specific concepts (surrogates, pseudonyms, entity kinds, etc.).

2. **SQL as the interface**: The benchmark tests an agent's ability to translate NL to SQL and get results from ClickHouse. mechubbench tests tool routing (e.g., "call `prepare_change_set` with these args"), not SQL generation.

3. **MCP-layer evaluation**: This evaluates the MCP surface (what tools are available and how to use them), which is SSDF's responsibility. The benchmark output (scorecards) is part of SSDF's evaluation evidence.

4. **No duplication**: mechubbench already has tool-call benchmarks for network automation. Adding SQL generation to mechubbench would require duplicating ClickHouse access and schema—a second benchmark harness, which Conway's Law suggests should live with the owning team (SSDF).

### Boundary

- **SSDF owns**: The corpus (questions), the scoring logic (SQL execution, audit check), the contract (manifest/scorecard schemas), the regression gate
- **External runner owns**: MCP client harnesses, model selection, run cadence, pass-rate policy (e.g., "80% pass rate minimum")

## Related Documentation

- [M8 eval harness design](docs/superpowers/specs/2026-06-12-ssdf-m8-eval-harness-design.md) — Full architecture and contract spec
- [External eval runner design](docs/superpowers/specs/2026-06-12-ssdf-m8-external-eval-runner-design.md) — How to build a runner (external repo)
- [CLAUDE.md M8 section](../CLAUDE.md#m8-agent-evals--) — Quick reference for developers

## License

Licensed under [MIT](../LICENSE).
