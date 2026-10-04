# ssdf-evals — M8 agent-eval harness (SSDF side)

SSDF builds **up to the MCP layer only**. This package owns the golden corpus,
the run-manifest contract, the deterministic scorer, scorecards, and the
regression gate. **Runner projects** (external repos) own the MCP client
harnesses (Claude Agent SDK, Ollama tool-calling, ...), model choice, run
cadence, and pass-rate policy.

Spec: `docs/superpowers/specs/2026-06-12-ssdf-m8-eval-harness-design.md`.

## What is this benchmark?

This package contains the **NL→SQL benchmark** for evaluating LLM tool-calling accuracy
on natural language queries against SSDF's ClickHouse firewall log database. The benchmark
tests whether an agent can:

1. Understand natural language questions about firewall traffic
2. Translate them to ClickHouse SQL queries
3. Route to the correct MCP tools
4. Return structured JSON answers that match SQL-based ground truth

For a detailed overview, including when to use this benchmark vs
[mechubbench](https://github.com/mechubsec/mechubbench), see `BENCHMARK.md`.

**Why not mechubbench?** mechubbench is a tool-call benchmark for network config tasks
(e.g., "prepare change set for overly permissive rules"). This NL→SQL benchmark is
domain-specific to SSDF's ClickHouse schema and firewall log analysis—Conway's Law
suggests it belongs with the team that owns the data (SSDF), not in a general-purpose
network automation harness.

## The contract (3 versioned artifacts)

1. `golden/core.yaml` — the questions. Runner sends each `question` to its
   agent with `answer_format` appended **verbatim**, and records the agent's
   final JSON answer.
2. `schemas/manifest.schema.json` — what the runner hands back (one JSON file
   per run). The manifest's `corpus_version` field is set by the runner to the
   git commit SHA of the SSDF repo (i.e. the corpus file) it ran against; the
   scorer copies it into the scorecard unverified — it exists for human/CI
   traceability of which corpus version the run targeted. Manifest question ids
   that are not in the run-tier corpus (e.g. sovereign questions in a public
   run) are ignored with a stderr warning.
3. `schemas/scorecard.schema.json` — what the scorer emits into `results/`.
   Scorecards are written to `results/<UTC-date>-<model>-<run_id>.json`
   (sanitized) and should be committed to git; git history is the eval
   database.

For a detailed description of the benchmark, including when to use it vs
[mechubbench](https://github.com/mechubsec/mechubbench), see `BENCHMARK.md`.

## Runner obligations

- Use a **dedicated eval-only principal token** (e.g. `eval-claude`,
  `eval-qwen`) added to the tier's `tokens.json` with expiry — never the
  regular agent token. `ssdf.audit` is the only trusted tool trace;
  self-reported tool calls are ignored.
- Bind to the real prod path: `https://198.51.100.152:30032/mcp` (sovereign) or
  `https://198.51.100.154:30033/mcp` (public) with `ssdf-ca.crt` trust — evals
  exercise prod auth by construction.
- Record per-question UTC `started`/`finished` (the scorer joins ssdf.audit on
  principal + this window ± `EVAL_AUDIT_SLOP_SECS`, default 5s).
- Run-tier subset: `sovereign` runs answer `tier: sovereign|both` questions;
  `public` runs answer `tier: public|both`.
- **IMPORTANT — audit integrity:** each runner uses a **dedicated eval-only
  principal** (e.g. `eval-claude`, `eval-qwen`) that is never shared with
  regular agents or other runners. Serial reuse of the same principal across
  runs is fine; two runs must never execute concurrently (or with overlapping
  ±slop audit windows) under the same principal — otherwise the audit
  tool-check window is untrustworthy and SSDF will not vouch for the
  scorecard.
- **Public-tier containment:** in a `tier: public` run, a question fails if
  ANY non-public tool appears in its audit window. Public tools are:
  `get_entity`, `locate`, `neighbors`, `find_path`, `topology_snapshot`.

## Scoring a run

    cd services/evals
    CH_HOST=<ct104> CH_PORT=8443 CH_SECURE=1 CH_CA_FILE=<ssdf-ca.crt> \
      CH_PASSWORD=<ssdf_ro pw> CH_AUDIT_VERIFY_PASSWORD=<ssdf_audit_verify pw> \
      uv run python -m ssdf_evals.score /path/to/manifest.json

Exit 0 = scored (scorecard written to `results/`, commit it — history is the
database). Exit 2 = config/contract/scoring error (covers mid-run failures).
Requires `CH_PASSWORD` + `CH_AUDIT_VERIFY_PASSWORD` at minimum; see CLAUDE.md
M8 section for the full env list.

A question passes only if its predicate **and** its audit tool-check pass.
Fail-closed: missing question = fail, runner error = fail, SQL error = fail.

**Sovereign-tier redaction:** a `reference_sql` predicate reads live lab
ClickHouse data. For a `tier: sovereign` manifest the scorecard's
`predicate_detail` never carries those raw rows — only counts, an overlap
count, and a sha256 of the sorted reference set (or a bare pass/fail bool for
`numeric_tolerance`). The unredacted values are written to a gitignored
`results/.detail/<scorecard-name>.json` sidecar for local debugging; never
commit that file.

## Regression gate

    uv run python -m ssdf_evals.regress results/<new-scorecard>.json

Exit 0 = no regressions. Exit 1 = regressions found (listed on stderr).
Exit 2 = unreadable/schema-invalid new scorecard or missing results dir. No
thresholds here — pass-rate floors (incl. the local-model sovereignty floor)
are runner-project policy.

## Tests

    uv run pytest -m "not integration"      # unit + corpus lint
    CH_HOST=... CH_PASSWORD=... CH_AUDIT_VERIFY_PASSWORD=... uv run pytest -m integration  # live corpus-SQL + audit join (see CLAUDE.md M8 for full env list)
