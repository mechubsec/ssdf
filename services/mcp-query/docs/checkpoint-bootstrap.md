# Bootstrapping a chain whose genesis expired before checkpointing

Linked from [checkpoint-key-rotation.md](checkpoint-key-rotation.md).

## When to use it

A chain's genesis row can age out of `ssdf.audit` (90-day TTL) before
checkpointing was ever enabled. Its oldest surviving row's `prev_hash` then
names an expired row that no checkpoint vouches for, so `verify_audit.py`
reports `missing_predecessor`/`unreachable`, and `checkpoint_audit.py` refuses
to sign an unverified chain. Every future row descends from it, so the chain
can never recover on its own. This happened to `tier='sovereign', server_id=''`.
Use the bootstrap once per such chain.

## The trust you give up

A bootstrap is trust on first use. By signing it, the operator attests that
the rows before the oldest surviving one **expired normally** rather than being
deleted early. The anchor is attested, not proven: those rows are gone either
way, so nothing available can confirm it. Everything after the anchor is
verified as usual. `verify_audit.py` marks such a chain
`anchor=attested(<checkpoint_ts>)` (a note, the chain still reports OK).

## Preconditions (checked by the job; any failure prints its reason, signs nothing for the chain, exits non-zero)

1. The chain has no checkpoints at all (one-time).
2. It has rows, none with `prev_hash == ""`.
3. Exactly one dangling `prev_hash` D (non-empty, names no present row).
4. `verify_tier` with no checkpoints reports only `missing_predecessor` and
   `unreachable`, and the only `missing_predecessor` is the row naming D (so no
   content edit, fork or duplicate).
5. Every row is reachable forward from D.

## How to run

Needs the signing key and verifying keyring, as for a normal run:

    uv run python scripts/checkpoint_audit.py --bootstrap sovereign
    uv run python scripts/checkpoint_audit.py --bootstrap evidence:SERVER_ID

CHAIN is `TIER` (server_id empty) or `TIER:SERVER_ID`. The job signs
`row_count=0, head_row_hash=D`, then continues in the same run and signs an
ordinary checkpoint (`row_count` = rows walked), so the chain verifies through
the bootstrap. Check `verify_audit.py` afterwards.

## Why `row_count == 0` is the marker

`row_count` is inside the signed digest, so someone with only database access
cannot turn an ordinary checkpoint into a bootstrap, and the normal job's
running totals are always >= 1. The verifier honours a signature-verified
`row_count == 0` checkpoint only if it is the chain's **earliest** verified
checkpoint (otherwise `invalid_bootstrap`, blocking). An honoured bootstrap is
exempt from the 88-day age rule and from the head-presence check (its head is
already gone); an unsigned or wrong-key one is ignored. Without `--bootstrap`
the job refuses to sign `row_count == 0`.

## Durability across later expiry

The bootstrap anchors only D. When the oldest surviving row later expires too,
the new dangling hash is reached only by bridging through archived rows in
`ssdf.audit_evidence`, back to D. That needs the archiver
(`scripts/archive_audit.py`) running continuously from now on; without it the
chain goes back to `missing_predecessor` once D's successor expires.
