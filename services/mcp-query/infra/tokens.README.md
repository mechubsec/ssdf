# Token file format

Keys are **digests**, never tokens: `sha256:<hex>` of the bearer the client
sends. The server hashes what a caller presents and matches that, so it never
holds a secret it could leak, and this file cannot be turned back into working
credentials.

Mode must be `0600`. The loader refuses a group- or world-readable file at
startup rather than warning — once the process is serving, the exposure has
already happened.

## Mint a token

```
python -m ssdf_mcp_query.mint_token --principal triage-agent \
    --allowed-tools query_flows,top_talkers --days 90
```

The token is printed **once**, on stdout; the entry to paste goes to stderr.
It is not recoverable afterwards. That is the point of the change.

Omit `--allowed-tools` to grant every tool. `--days 0` means no expiry.

## `created_at` and `whoami`

`mint_token` writes `created_at` (ISO-8601 UTC) on every new entry. It is
optional and informational: older entries without it load fine. A malformed
value is a startup `ConfigError`, like `not_after`.

Any valid token may call the `whoami` tool, whatever its `allowed_tools`, on both
tiers. It returns only the caller's own `{principal, created_at, expires_at,
local_only}` (null when unset), never digests, other principals or the tool
list. An expired token is still denied, and the call is rate-limited and audited
like any other. Use it to warn before `expires_at`.

## Sovereign tier requires `local_only` (M16e)

A `tier="sovereign"` build refuses to authenticate any token whose entry does
not set `"local_only": true`. This is not a preference the token can override
by claiming to be local elsewhere (a manifest field, a client header) — the
server drops the token from its verifier entirely before auth runs. Set it via
`mint_token --local-only`, or add `"local_only": true` by hand to an existing
entry. A token without it still works fine against a `tier="public"` build; the
attestation only gates the sovereign tier, and it exists because a hosted-model
runner reading real lab data through a sovereign token is exactly what leaked
lab IPs and rule names into committed eval scorecards.

**Migration:** existing sovereign-tier (ct106-class) token files predate this
field, so every entry in them is currently unattested and will be rejected once
this ships. Re-mint each principal that should keep sovereign access with
`--local-only`, or add the field by hand and restart; there is no default that
preserves old behavior; unattested means untrusted.

## Rotate

Add the new entry alongside the old, restart, move clients across, delete the
old entry, restart again. Two entries may coexist; two entries resolving to the
same digest may not, and the loader refuses that rather than silently letting
one shadow the other's grants.

## Migrating a legacy file

A key that is not a digest is treated as a plaintext token: it is hashed at load
so the deployment keeps working, and the principal is named in a startup warning
on stderr. Re-mint those tokens. **Treat every one of them as compromised** — a
leaked token and a live one are indistinguishable, which is exactly why they
should not have been stored in the first place.
