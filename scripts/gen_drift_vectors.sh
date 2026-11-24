#!/usr/bin/env bash
# Generates services/mcp-query/tests/fixtures/drift_chain_vectors.json using only
# jq and sha256sum (never this repo's Python), so the tests pin the hash format
# independently of the implementation.
#   scripts/gen_drift_vectors.sh > services/mcp-query/tests/fixtures/drift_chain_vectors.json
set -euo pipefail

prev=""
vectors=()

# emit TS SERVER INTENT FLOW VERDICT DEVICE RULES_JSON LABMODE
emit() {
  local ts=$1 server=$2 intent=$3 flow=$4 verdict=$5 device=$6 rules=$7 lab=$8 evidence="ev/$4"
  local canon row_hash
  canon=$(jq -cn --arg ts "$ts" --arg s "$server" --arg i "$intent" --arg f "$flow" \
    --arg v "$verdict" --arg d "$device" --argjson r "$rules" --arg e "$evidence" --argjson l "$lab" \
    '[$ts,$s,$i,$f,$v,$d,$r,$e,$l]')
  row_hash=$(printf '%s\n%s' "$prev" "$canon" | sha256sum | cut -d' ' -f1)
  vectors+=("$(jq -cn --arg ts "$ts" --arg s "$server" --arg i "$intent" --arg f "$flow" \
    --arg v "$verdict" --arg d "$device" --argjson r "$rules" --arg e "$evidence" --argjson l "$lab" \
    --arg p "$prev" --arg c "$canon" --arg h "$row_hash" \
    '{row:{ts:$ts,server_id:$s,intent_commit:$i,flow_or_isolation_id:$f,verdict:$v,device:$d,device_rule_ids:$r,evidence_ref:$e,labmode:$l},prev_hash:$p,canonical:$c,row_hash:$h}')")
  prev=$row_hash
}

emit 2026-11-24T10:00:00.123Z srv-a.example.com 0123abc flow-1 consistent fw1.example.com '["r1","r2"]' 1
emit 2026-11-24T10:00:01.000Z srv-a.example.com 0123abc flow-2 violating fw1.example.com '["r3"]' 1
emit 2026-11-24T10:00:02.456Z srv-a.example.com 0123abc flow-3 unverifiable $'fw-é"x\ny' '["r4"]' 1
emit 2026-11-24T10:00:03.789Z srv-a.example.com 0123abc iso-1 over_permissive fw2.example.com '[]' 0

printf '%s\n' "${vectors[@]}" | jq -s .
