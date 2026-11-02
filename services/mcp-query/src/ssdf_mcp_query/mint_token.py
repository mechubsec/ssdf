"""Mint a bearer token and print the token-file entry for it (issue #7).

Once the token file holds digests, an operator can no longer read a token back
out of it -- that is the point. So minting has to hand the plaintext over exactly
once, at creation, and there has to be a tool that does it.

    python -m ssdf_mcp_query.mint_token --principal triage-agent \\
        --allowed-tools query_flows,top_talkers --days 90

Prints the token on stdout and the JSON entry on stderr, so a caller can capture
just the secret with a pipe while a human still sees what to paste into the file.

Rotation: add the new entry alongside the old one, restart, move clients across,
then delete the old entry and restart again. Two entries may coexist; two entries
resolving to the same digest may not, and the loader refuses that.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import sys

from .tokenstore import digest_for, mint_token


def build_entry(
    principal: str,
    allowed_tools: list[str] | None,
    days: int | None,
    local_only: bool = False,
) -> tuple[str, dict]:
    """Return ``(token, {digest: entry})`` for a freshly minted token."""
    token = mint_token()
    now = _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0)
    entry: dict = {"principal": principal, "created_at": now.isoformat()}
    if allowed_tools:
        entry["allowed_tools"] = allowed_tools
    if local_only:
        entry["local_only"] = True
    if days is not None:
        # Whole seconds (via `now`): sub-second precision is noise in a file a human edits.
        entry["not_after"] = (now + _dt.timedelta(days=days)).isoformat()
    return token, {digest_for(token): entry}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--principal", required=True, help="audit identity for this token")
    parser.add_argument(
        "--allowed-tools",
        default="",
        help="comma-separated tool allow-list; omit to grant every tool",
    )
    parser.add_argument(
        "--days",
        type=int,
        default=90,
        help="days until not_after (default 90); pass 0 for no expiry",
    )
    parser.add_argument(
        "--local-only",
        action="store_true",
        help="attest this token drives a model on operator-controlled infrastructure "
        "(M16e); required for a token to authenticate against a sovereign-tier build",
    )
    args = parser.parse_args(argv)

    tools = [t.strip() for t in args.allowed_tools.split(",") if t.strip()] or None
    token, entry = build_entry(
        args.principal, tools, None if args.days == 0 else args.days, args.local_only
    )

    print(token)
    print(
        "\nAdd to the token file (mode 0600), then restart the service:\n"
        + json.dumps(entry, indent=2)
        + "\n\nThe token above is shown ONCE. It is not recoverable from the file.",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
