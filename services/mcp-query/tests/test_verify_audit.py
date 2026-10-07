import base64
import datetime as dt

from ssdf_mcp_query.audit_chain import compute_row_hash
from ssdf_mcp_query.checkpoint_verify import Checkpoint, key_fingerprint
from ssdf_mcp_query.verify_audit import verify_tier


def _keyring(verifying_key: bytes) -> dict[str, bytes]:
    return {key_fingerprint(verifying_key): verifying_key}


def _chain(n, tier="sovereign", first_prev=""):
    """Build n correctly-chained rows for one tier."""
    rows = []
    prev = first_prev
    for i in range(n):
        row = dict(
            ts=dt.datetime(2026, 6, 10, 12, 0, i, 0, tzinfo=dt.timezone.utc),
            principal="agent",
            tier=tier,
            tool=f"t{i}",
            args="{}",
            data_classes=["topology"],
            decision="allow",
            row_count=i,
            error="",
        )
        row["prev_hash"] = prev
        row["row_hash"] = compute_row_hash(prev, row)
        prev = row["row_hash"]
        rows.append(row)
    return rows


def test_clean_chain_has_no_issues():
    assert verify_tier(_chain(4)) == []


def test_detects_content_edit():
    rows = _chain(4)
    rows[2]["tool"] = "TAMPERED"  # stored row_hash no longer matches recomputed
    issues = verify_tier(rows)
    assert any(i["type"] == "content_edit" for i in issues)


def test_detects_deletion_of_predecessor():
    rows = _chain(4)
    del rows[1]  # row[2].prev_hash now names a missing row_hash
    issues = verify_tier(rows)
    assert any(i["type"] == "missing_predecessor" for i in issues)


def test_legacy_unhashed_rows_are_not_issues():
    """Rows written before migration 009 have prev_hash='' / row_hash='' (column
    DEFAULT). The first *hashed* row per tier is that tier's chain start; legacy
    rows must not be flagged."""
    legacy = dict(
        ts=dt.datetime(2026, 6, 9, 12, 0, 0, 0, tzinfo=dt.timezone.utc),
        principal="agent",
        tier="sovereign",
        tool="old",
        args="{}",
        data_classes=["topology"],
        decision="allow",
        row_count=0,
        error="",
        prev_hash="",
        row_hash="",
    )
    rows = [legacy] + _chain(3)
    assert verify_tier(rows) == []


def test_detects_unreachable_orphan():
    rows = _chain(3)
    orphan = dict(
        ts=dt.datetime(2026, 6, 10, 13, 0, 0, 0, tzinfo=dt.timezone.utc),
        principal="agent",
        tier="sovereign",
        tool="x",
        args="{}",
        data_classes=["topology"],
        decision="allow",
        row_count=0,
        error="",
        prev_hash="deadbeef",
        row_hash="feedface",
    )
    rows.append(orphan)
    issues = verify_tier(rows)
    assert any(i["type"] in ("unreachable", "missing_predecessor") for i in issues)


def _evidence_chain(n, server_id, first_prev=""):
    """Build n correctly-chained evidence rows for one writer."""
    rows = []
    prev = first_prev
    for i in range(n):
        row = dict(
            ts=dt.datetime(2026, 8, 20, 12, 0, i, 0, tzinfo=dt.timezone.utc),
            principal="agent:mecmcp",
            tier="evidence",
            tool="evidence:proposal",
            args=('{"server_id":"' + server_id + '","run_id":"run-1","segment_seq":0}'),
            data_classes=["device:vsrx-ci"],
            decision="",
            row_count=1,
            error="",
        )
        row["prev_hash"] = prev
        row["row_hash"] = compute_row_hash(prev, row)
        prev = row["row_hash"]
        rows.append(row)
    return rows


def test_two_writers_are_verified_as_separate_chains():
    """The evidence tier has many writers; one chain per tier cannot work.

    Fifteen MCP servers write ``tier='evidence'``. Chaining per tier would need
    every writer to serialise against a shared head — there is no such lock, so
    each seeds ``prev_hash=""`` and the tier acquires one accepted root per
    server. Grouping by writer gives each exactly one root, which is what makes
    a deleted run detectable (ssdf#47).
    """
    from ssdf_mcp_query.verify_audit import group_key

    rows = _evidence_chain(3, "mecmcp-950") + _evidence_chain(3, "mecmcp-960")

    keys = {group_key(r) for r in rows}
    assert keys == {
        ("evidence", "mecmcp-950"),
        ("evidence", "mecmcp-960"),
    }, "each writer must be its own chain"

    for key in keys:
        subset = [r for r in rows if group_key(r) == key]
        assert verify_tier(subset) == [], f"{key} must verify clean on its own"


def test_a_deleted_run_leaves_a_missing_predecessor():
    """The failure this whole mechanism exists to catch.

    A run that continues its writer's chain (``resume_from``) means deleting
    that run outright breaks the link its successor names — rather than removing
    an entire independent root, which leaves nothing to notice.
    """
    first_run = _evidence_chain(2, "mecmcp-950")
    second_run = _evidence_chain(2, "mecmcp-950", first_prev=first_run[-1]["row_hash"])

    surviving = second_run  # the first run is deleted wholesale

    issues = verify_tier(surviving)
    assert any(i["type"] == "missing_predecessor" for i in issues), (
        "deleting a whole run must be visible; it is only visible because the "
        "later run chained onto the earlier one"
    )


def test_rows_without_a_server_id_group_by_tier_alone():
    """Sovereign rows carry no server_id and must keep verifying as they did."""
    from ssdf_mcp_query.verify_audit import group_key

    assert group_key(_chain(1)[0]) == ("sovereign", "")


def test_an_evidence_row_without_a_writer_is_a_violation():
    """An evidence row must name the chain it belongs to.

    Grouping such a row under the tier alone is not a harmless default: several
    malformed writers land in one bucket, each contributes its own root, and the
    result verifies as clean. That is the deletion blind spot the per-writer
    grouping exists to close, reached from the other side — so an evidence row
    with no usable ``server_id`` has to be an issue, not a fallback.
    """
    from ssdf_mcp_query.verify_audit import writer_issue

    assert writer_issue({"tier": "evidence", "args": "", "row_hash": "sha256:a"})
    assert writer_issue({"tier": "evidence", "args": "not json", "row_hash": "sha256:b"})
    assert writer_issue({"tier": "evidence", "args": '{"server_id": 7}', "row_hash": "sha256:c"})
    assert writer_issue({"tier": "evidence", "args": '{"server_id": ""}', "row_hash": "sha256:d"})
    assert not writer_issue(
        {"tier": "evidence", "args": '{"server_id": "junos-950"}', "row_hash": "sha256:e"}
    )


def test_a_sovereign_row_without_a_writer_is_not_a_violation():
    """The 20,193 existing sovereign rows name no writer and never did.

    Requiring one of them would turn every historical row into an issue, which
    is a rule about a different tier applied where it was never promised.
    """
    from ssdf_mcp_query.verify_audit import writer_issue

    assert not writer_issue({"tier": "sovereign", "args": "", "row_hash": "sha256:f"})


def test_detects_a_replayed_duplicate_row():
    """A retry after an ambiguous timeout lands the same row twice.

    An HTTP INSERT that times out while ClickHouse is still committing leaves
    the sink unable to tell whether the row landed. Its pre-retry high-water
    read can say "nothing", the retry inserts, and the original commits too --
    two identical rows in a plain MergeTree.

    The chain checks alone cannot see this: the duplicate carries the *same*
    row_hash, so hash-keyed lookups collapse the pair into one entry and every
    linkage and reachability check passes. Counting occurrences is what makes
    it visible.
    """
    rows = _chain(4)
    rows.append(dict(rows[2]))  # the replayed row, byte-for-byte

    issues = verify_tier(rows)

    duplicates = [i for i in issues if i["type"] == "duplicate_row"]
    assert len(duplicates) == 1, issues
    assert duplicates[0]["row_hash"] == rows[2]["row_hash"]


def test_a_clean_chain_reports_no_duplicates():
    """Guards the counting against firing on ordinary chains."""
    assert not [i for i in verify_tier(_chain(6)) if i["type"] == "duplicate_row"]


def test_dedup_token_counts_utf8_bytes_not_code_points():
    """The token must be byte-identical to the Rust sink's, or dedup fails open.

    Python's ``len()`` counts code points and Rust's ``str::len()`` counts UTF-8
    bytes. For an ASCII identifier they agree, which is why this went unnoticed;
    for anything else they diverge, and a retry issued by the other
    implementation carries a different token. ClickHouse then sees a new block
    and the duplicate lands -- the failure the token exists to prevent, arrived
    at by disagreeing about how to spell it.
    """
    from ssdf_mcp_query.audit_chain import dedup_token

    # Known-answer vectors, shared with the Rust `dedup_token` and with
    # scripts/verify_evidence_contract.py. Changing either side alone breaks
    # deduplication silently, so these are pinned rather than computed.
    assert dedup_token("junos-950", "run-7", 42) == "9:junos-950:5:run-7:42"
    assert dedup_token("café", "run-7", 0) == "5:café:5:run-7:0"

    # The encoding is injective even when an identifier contains the separator.
    assert dedup_token("a:b", "c", 1) != dedup_token("a", "b:c", 1)


# MEC-565: checkpoint-anchored verification. The fixtures below (key +
# signature) were produced by the actual Rust `mecmcp-audit-checkpoint`
# binary (mechubsec/mecmcp, v0.26.0) against the exact `head_row_hash` used
# here -- see test_checkpoint_verify.py's module docstring for the generation
# commands. This is the same precedent as the dedup_token known-answer
# vectors: an independently "equivalent-looking" fixture is exactly the thing
# that would hide a real cross-implementation mismatch.
_VERIFYING_KEY = base64.b64decode("eq9vdjiCq9yRMn3C7MQmI6QFOkxq52Bb4PRExbLQ0GM=")
_OTHER_KEY = base64.b64decode("AtqHG8dIiOhQanjTfmfJcED8/U6XfQLxeyANTVzwusk=")
_VERIFYING_KEYRING = _keyring(_VERIFYING_KEY)
_OTHER_KEYRING = _keyring(_OTHER_KEY)


def _expired_genesis_scenario():
    """A chain whose genesis has aged out of ssdf.audit: two fresh rows
    continuing from a first_run whose own rows are no longer present. Returns
    (surviving_rows, checkpoint_for_the_expired_genesis_run)."""
    first_run = _chain(2)
    surviving = _chain(2, first_prev=first_run[-1]["row_hash"])
    checkpoint = Checkpoint(
        tier="sovereign",
        server_id="",
        row_count=2,
        head_row_hash=first_run[-1]["row_hash"],
        checkpoint_ts="2026-09-15T00:00:00.000Z",
        signature=(
            "YpCXYBv7x5nVgoxe8z2HFu5jAKUQIb8xrAhJ/9TP20bMwm20AqgEB0b4"
            "fsRpshlCUAFFYSXzhnYNwGhAIzLYBg=="
        ),
        key_id="7b5c53a1eeb8048b",
    )
    return surviving, checkpoint


# "now" instants used by the fixed MEC-565 checkpoint fixture above
# (checkpoint_ts="2026-09-15T00:00:00.000Z"). The anchor-selection logic only
# trusts a checkpoint once it is old enough that the rows it stands in for
# could have actually expired past the 90-day TTL (minus the schedule's
# slack) -- see _is_old_enough_to_anchor.
_NOW_CHECKPOINT_OLD_ENOUGH = dt.datetime(2026, 12, 15, tzinfo=dt.timezone.utc)  # ~91 days later
_NOW_CHECKPOINT_TOO_FRESH = dt.datetime(2026, 9, 20, tzinfo=dt.timezone.utc)  # 5 days later


def test_expired_genesis_with_no_checkpoint_is_still_unreachable():
    """Unchanged legacy behaviour: no checkpoint configured means an expired
    genesis still reports every surviving row as unreachable (plus
    missing_predecessor for the row whose prev_hash names the now-gone
    genesis -- both are legitimate without a checkpoint to vouch for it)."""
    surviving, _ = _expired_genesis_scenario()
    issues = verify_tier(surviving)
    assert {i["type"] for i in issues} == {"unreachable", "missing_predecessor"}
    assert len([i for i in issues if i["type"] == "unreachable"]) == len(surviving)


def test_expired_genesis_with_valid_checkpoint_verifies_clean():
    surviving, checkpoint = _expired_genesis_scenario()
    issues = verify_tier(
        surviving,
        checkpoints=[checkpoint],
        keyring=_VERIFYING_KEYRING,
        now=_NOW_CHECKPOINT_OLD_ENOUGH,
    )
    assert issues == []


def test_expired_genesis_with_checkpoint_but_no_verifying_key_stays_unreachable():
    """A checkpoint exists but there is nothing to verify it against -- must
    fail closed to 'unverifiable', not silently trust it."""
    surviving, checkpoint = _expired_genesis_scenario()
    issues = verify_tier(
        surviving, checkpoints=[checkpoint], keyring=None, now=_NOW_CHECKPOINT_OLD_ENOUGH
    )
    assert any(i["type"] == "unverifiable_checkpoint" for i in issues)
    assert all(
        i["type"] in ("unverifiable_checkpoint", "unreachable", "missing_predecessor")
        for i in issues
    )


def test_expired_genesis_with_checkpoint_signed_by_wrong_key_stays_unreachable():
    surviving, checkpoint = _expired_genesis_scenario()
    issues = verify_tier(
        surviving,
        checkpoints=[checkpoint],
        keyring=_OTHER_KEYRING,
        now=_NOW_CHECKPOINT_OLD_ENOUGH,
    )
    assert any(i["type"] == "unverifiable_checkpoint" for i in issues)
    assert all(
        i["type"] in ("unverifiable_checkpoint", "unreachable", "missing_predecessor")
        for i in issues
    )


def test_a_checkpoint_that_does_not_match_any_dangling_row_does_not_mask_a_gap():
    """A checkpoint that verifies but names a hash no surviving row's
    prev_hash actually points to (e.g. an entire later run was deleted after
    the checkpoint was taken) must not suppress the missing_predecessor it
    would otherwise report -- the anchor only exempts rows that actually
    chain from it."""
    _, checkpoint = _expired_genesis_scenario()
    unrelated = _chain(2, first_prev="some-other-already-expired-run-head")
    issues = verify_tier(
        unrelated,
        checkpoints=[checkpoint],
        keyring=_VERIFYING_KEYRING,
        now=_NOW_CHECKPOINT_OLD_ENOUGH,
    )
    assert any(i["type"] == "missing_predecessor" for i in issues)


def test_a_checkpoint_near_the_chain_tip_is_not_selected_over_the_matching_one():
    """With a daily checkpoint schedule, the *latest* checkpoint for a chain
    sits at or near the current tip, not at the expired genesis's successor.
    Selecting "the latest checkpoint" rather than "the checkpoint whose
    head_row_hash matches (directly or via a bridge) the actual dangling
    prev_hash" would mean every chain reports tamper indefinitely once its
    genesis ages out. A second, unrelated, validly-signed checkpoint that is
    more recent (by checkpoint_ts) but does not match any dangling prev_hash
    must not be selected as the anchor, and the one that does match must
    still be used.

    Both checkpoints are given real signatures here (MEC-565 F1 made every
    checkpoint's signature checked, not just the one selected as anchor, so
    a deliberately-unverifiable "irrelevant" checkpoint would otherwise make
    this test fail for an unrelated reason)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    signing_key = Ed25519PrivateKey.generate()
    verifying_key = signing_key.public_key().public_bytes_raw()

    first_run = _chain(2)
    surviving = _chain(2, first_prev=first_run[-1]["row_hash"])
    matching_checkpoint = _signed_checkpoint(
        signing_key, first_run[-1]["row_hash"], "2026-09-15T00:00:00.000Z", row_count=2
    )
    near_tip_checkpoint = _signed_checkpoint(
        signing_key, surviving[-1]["row_hash"], "2026-09-16T00:00:00.000Z", row_count=4
    )
    issues = verify_tier(
        surviving,
        checkpoints=[near_tip_checkpoint, matching_checkpoint],
        keyring=_keyring(verifying_key),
        now=_NOW_CHECKPOINT_OLD_ENOUGH,
    )
    assert issues == []


def test_a_checkpoint_too_fresh_to_have_expired_rows_is_premature_truncation():
    """A checkpoint taken only days ago cannot legitimately be standing in
    for rows that are supposed to survive another ~85 days under the 90-day
    TTL. Trusting it anyway would let a recent, unexpired prefix be deleted
    and immediately covered by a checkpoint anchoring the gap, defeating
    tamper-evidence entirely."""
    surviving, checkpoint = _expired_genesis_scenario()
    issues = verify_tier(
        surviving,
        checkpoints=[checkpoint],
        keyring=_VERIFYING_KEYRING,
        now=_NOW_CHECKPOINT_TOO_FRESH,
    )
    assert any(i["type"] == "premature_truncation" for i in issues)
    # The rejected anchor must not be substituted with silent trust either --
    # the surviving rows fall back to exactly the no-checkpoint behaviour.
    assert any(i["type"] == "unreachable" for i in issues)


def test_genesis_still_present_ignores_a_checkpoint_for_reachability_but_still_checks_its_signature():
    """Signature is checked even when genesis is present."""
    rows = _chain(4)
    malformed = Checkpoint(
        tier="sovereign",
        server_id="",
        row_count=1,
        head_row_hash="irrelevant",
        checkpoint_ts="2026-01-01T00:00:00.000Z",
        signature="not-valid-base64!!",
        key_id="deadbeef",
    )
    issues = verify_tier(rows, checkpoints=[malformed], keyring=_VERIFYING_KEYRING)
    assert issues == [{"type": "unverifiable_checkpoint", "row_hash": "irrelevant"}]


def test_genesis_still_present_and_no_verifying_key_ignores_a_malformed_checkpoint():
    """Without a verifying key there is nothing to check a checkpoint's
    signature against, so self-verification stays exactly as silent for a
    malformed checkpoint as it always has -- this is the one case where a
    checkpoint genuinely has zero effect."""
    rows = _chain(4)
    malformed = Checkpoint(
        tier="sovereign",
        server_id="",
        row_count=1,
        head_row_hash="irrelevant",
        checkpoint_ts="2026-01-01T00:00:00.000Z",
        signature="not-valid-base64!!",
        key_id="deadbeef",
    )
    issues = verify_tier(rows, checkpoints=[malformed])
    assert issues == []


def test_checkpoint_does_not_mask_a_real_tamper_on_the_surviving_rows():
    """A valid checkpoint anchors reachability; it must not blind the other
    checks (content_edit, missing_predecessor) to tampering within the rows
    that DO still survive."""
    surviving, checkpoint = _expired_genesis_scenario()
    surviving[1]["tool"] = "TAMPERED"
    issues = verify_tier(
        surviving,
        checkpoints=[checkpoint],
        keyring=_VERIFYING_KEYRING,
        now=_NOW_CHECKPOINT_OLD_ENOUGH,
    )
    assert any(i["type"] == "content_edit" for i in issues)


def _signed_checkpoint(
    signing_key, head_row_hash: str, checkpoint_ts: str, row_count: int = 1
) -> Checkpoint:
    from ssdf_mcp_query.checkpoint_verify import canonical_digest

    unsigned = Checkpoint(
        tier="sovereign",
        server_id="",
        row_count=row_count,
        head_row_hash=head_row_hash,
        checkpoint_ts=checkpoint_ts,
        signature="",
        key_id=key_fingerprint(signing_key.public_key().public_bytes_raw()),
    )
    signature = base64.b64encode(signing_key.sign(canonical_digest(unsigned))).decode()
    return Checkpoint(**{**unsigned.__dict__, "signature": signature})


def test_bridge_through_evidence_rows_anchors_a_predecessor_the_checkpoint_does_not_match():
    """Under a real row-level TTL, the row that has just aged out of
    ssdf.audit is a checkpoint head only when the TTL boundary happens
    to land exactly on a scheduled checkpoint. In general -- hourly rows,
    daily checkpoints, TTL expiry at an arbitrary time of day -- the
    predecessor that most recently expired sits between two checkpoints, not
    at one. Bridging through the evidence tier (which outlives ssdf.audit's
    TTL by a wide margin) is what lets the chain still anchor in that case."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    signing_key = Ed25519PrivateKey.generate()
    verifying_key = signing_key.public_key().public_bytes_raw()

    full_chain = _chain(5)  # ts base 2026-06-10, rows 12:00:00 .. 12:00:04
    checkpoint = _signed_checkpoint(
        # After the chain's own rows, so this fixture's surviving rows are
        # never "newer than the latest checkpoint" -- this test is about
        # bridging/anchoring, not about MEC-1634's stale_checkpoint check.
        signing_key,
        full_chain[0]["row_hash"],
        "2026-06-11T00:00:00.000Z",
    )
    bridge_rows = full_chain[1:3]  # rows between the checkpoint head and the TTL boundary
    surviving = full_chain[3:]  # all that remains in ssdf.audit
    now = dt.datetime(2026, 9, 19, tzinfo=dt.timezone.utc)  # ~100 days later: old enough

    issues_without_bridge = verify_tier(
        surviving, checkpoints=[checkpoint], keyring=_keyring(verifying_key), now=now
    )
    assert any(i["type"] == "missing_predecessor" for i in issues_without_bridge), (
        "the checkpoint head does not match the dangling prev_hash directly, "
        "so without a bridge the gap must still be reported"
    )

    issues_with_bridge = verify_tier(
        surviving,
        checkpoints=[checkpoint],
        bridge_rows=bridge_rows,
        keyring=_keyring(verifying_key),
        now=now,
    )
    assert issues_with_bridge == []


def test_bridge_rejects_a_tampered_intermediate_row():
    """A bridge row's own content is recomputed and checked before its
    prev_hash is trusted to continue the walk -- a row changed after it was
    archived must not be usable to extend an anchor past where it actually
    reaches."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    signing_key = Ed25519PrivateKey.generate()
    verifying_key = signing_key.public_key().public_bytes_raw()

    full_chain = _chain(5)
    checkpoint = _signed_checkpoint(
        signing_key, full_chain[0]["row_hash"], "2026-01-01T00:00:00.000Z"
    )
    bridge_rows = [dict(full_chain[1]), dict(full_chain[2])]
    bridge_rows[0]["tool"] = "TAMPERED"  # content changed after row_hash was stored
    surviving = full_chain[3:]
    now = dt.datetime(2026, 4, 15, tzinfo=dt.timezone.utc)

    issues = verify_tier(
        surviving,
        checkpoints=[checkpoint],
        bridge_rows=bridge_rows,
        keyring=_keyring(verifying_key),
        now=now,
    )
    assert any(i["type"] == "content_edit" for i in issues)
    assert any(i["type"] == "missing_predecessor" for i in issues)


def test_recent_checkpoint_head_missing_is_detected():
    """A checkpoint anchored at the current chain tip followed by deletion
    of the rows at and after that head must be caught immediately, not only
    ~90 days later when genesis itself ages out. The chain's genesis is
    untouched here, so the existing anchor-selection path (which only runs
    once genesis is absent) never sees it; this check must run regardless of
    whether genesis survives."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    signing_key = Ed25519PrivateKey.generate()
    verifying_key = signing_key.public_key().public_bytes_raw()

    full_chain = _chain(5)
    checkpoint = _signed_checkpoint(
        signing_key, full_chain[-1]["row_hash"], "2026-04-01T00:00:00.000Z"
    )
    truncated = full_chain[:3]  # rows 4-5 (the checkpointed head) deleted
    now = dt.datetime(2026, 4, 15, tzinfo=dt.timezone.utc)  # 14 days later: not old enough

    issues = verify_tier(
        truncated, checkpoints=[checkpoint], keyring=_keyring(verifying_key), now=now
    )
    assert any(
        i["type"] == "checkpoint_head_missing" and i["row_hash"] == full_chain[-1]["row_hash"]
        for i in issues
    )


def test_old_enough_checkpoint_head_missing_is_not_flagged():
    """The same absent head is NOT reported once the checkpoint is old
    enough that its rows could have legitimately TTL-expired -- this check
    only covers the window where expiry cannot yet explain the gap."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    signing_key = Ed25519PrivateKey.generate()
    verifying_key = signing_key.public_key().public_bytes_raw()

    full_chain = _chain(5)
    checkpoint = _signed_checkpoint(
        signing_key, full_chain[-1]["row_hash"], "2026-01-01T00:00:00.000Z"
    )
    truncated = full_chain[:3]
    now = dt.datetime(2026, 4, 15, tzinfo=dt.timezone.utc)  # ~104 days later: old enough

    issues = verify_tier(
        truncated, checkpoints=[checkpoint], keyring=_keyring(verifying_key), now=now
    )
    assert not any(i["type"] == "checkpoint_head_missing" for i in issues)


def test_detects_a_forked_chain():
    """Two rows naming the same prev_hash each still link and reach
    correctly on their own -- neither content-integrity nor reachability
    sees anything wrong with either branch, so forks need their own check.
    An exact duplicate (identical row_hash) must not also count as a fork;
    that is already `duplicate_row`'s job."""
    rows = _chain(3)
    genuine_child = rows[-1]
    sibling = dict(genuine_child, tool="sibling", row_count=99)
    sibling["row_hash"] = compute_row_hash(sibling["prev_hash"], sibling)
    rows.append(sibling)

    issues = verify_tier(rows)

    forks = [i for i in issues if i["type"] == "fork"]
    assert {f["row_hash"] for f in forks} == {genuine_child["row_hash"], sibling["row_hash"]}


def test_two_genesis_rows_is_also_a_fork():
    """A second row with prev_hash == "" is the same shape of ambiguity as a
    fork deeper in the chain, and must be caught the same way."""
    rows = _chain(2)
    second_genesis = dict(rows[0], tool="other-genesis", row_count=100)
    second_genesis["row_hash"] = compute_row_hash("", second_genesis)
    rows.append(second_genesis)

    issues = verify_tier(rows)

    forks = [i for i in issues if i["type"] == "fork"]
    assert {f["row_hash"] for f in forks} == {rows[0]["row_hash"], second_genesis["row_hash"]}


def test_a_replayed_duplicate_is_not_also_reported_as_a_fork():
    rows = _chain(4)
    rows.append(dict(rows[2]))  # byte-for-byte replay, same row_hash

    issues = verify_tier(rows)

    assert not [i for i in issues if i["type"] == "fork"]


def test_recent_checkpoint_with_invalid_signature_is_not_skipped_silently():
    """A row in audit_checkpoints that fails signature verification means
    someone with INSERT on that table wrote something wrong -- that must be
    visible, not swallowed by `continue`."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    signing_key = Ed25519PrivateKey.generate()
    wrong_key = Ed25519PrivateKey.generate()
    verifying_key = wrong_key.public_key().public_bytes_raw()

    full_chain = _chain(5)
    checkpoint = _signed_checkpoint(
        signing_key, full_chain[-1]["row_hash"], "2026-04-01T00:00:00.000Z"
    )
    truncated = full_chain[:3]
    now = dt.datetime(2026, 4, 15, tzinfo=dt.timezone.utc)  # not old enough to anchor

    issues = verify_tier(
        truncated, checkpoints=[checkpoint], keyring=_keyring(verifying_key), now=now
    )

    assert any(
        i["type"] == "unverifiable_checkpoint" and i["row_hash"] == full_chain[-1]["row_hash"]
        for i in issues
    )


def test_checkpoint_head_missing_is_not_masked_by_a_replayed_but_too_young_bridge_row():
    """A bridge row that is not old enough to have legitimately reached the
    evidence tier must not be accepted as proof a checkpoint head survives."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    signing_key = Ed25519PrivateKey.generate()
    verifying_key = signing_key.public_key().public_bytes_raw()

    full_chain = _chain(5)
    checkpoint = _signed_checkpoint(
        signing_key, full_chain[3]["row_hash"], "2026-04-01T00:00:00.000Z"
    )
    now = dt.datetime(2026, 4, 15, tzinfo=dt.timezone.utc)  # 14 days later: not old enough

    replacement_tail = _chain(2, first_prev=full_chain[1]["row_hash"])
    live_rows = full_chain[:2] + replacement_tail

    issues_alone = verify_tier(
        live_rows, checkpoints=[checkpoint], keyring=_keyring(verifying_key), now=now
    )
    assert any(i["type"] == "checkpoint_head_missing" for i in issues_alone)

    original_tail = full_chain[2:4]  # the real rows 3-4, replayed verbatim
    issues_with_bridge = verify_tier(
        live_rows,
        checkpoints=[checkpoint],
        bridge_rows=original_tail,
        keyring=_keyring(verifying_key),
        now=now,
    )
    assert any(i["type"] == "checkpoint_head_missing" for i in issues_with_bridge), (
        "a too-young bridge row must not vouch for a checkpoint head it did not "
        "legitimately outlive"
    )


def test_checkpoint_head_missing_is_not_masked_by_a_content_tampered_bridge_row():
    """Even when a bridge row's age alone would pass, a content tamper must
    still be caught before it can vouch for a checkpoint head -- presence
    under the right dict key is not proof the stored content is genuine."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    signing_key = Ed25519PrivateKey.generate()
    verifying_key = signing_key.public_key().public_bytes_raw()

    full_chain = _chain(5)  # ts base 2026-06-10
    checkpoint = _signed_checkpoint(
        signing_key, full_chain[3]["row_hash"], "2026-09-05T00:00:00.000Z"
    )
    now = dt.datetime(2026, 9, 10, tzinfo=dt.timezone.utc)  # checkpoint itself only 5 days old

    live_rows = full_chain[:2]  # rows 3-5 no longer in ssdf.audit
    bridge_row = dict(full_chain[3])
    bridge_row["tool"] = "TAMPERED"  # dict key (row_hash) unchanged; content no longer matches

    issues = verify_tier(
        live_rows,
        checkpoints=[checkpoint],
        bridge_rows=[bridge_row],
        keyring=_keyring(verifying_key),
        now=now,
    )
    assert any(i["type"] == "checkpoint_head_missing" for i in issues)


def test_checkpoint_head_missing_is_not_flagged_when_bridge_row_is_genuinely_archived():
    """The positive case: a bridge row that is both old enough (per
    ``_AUDIT_TTL_DAYS - _CHECKPOINT_INTERVAL_SLACK_DAYS``) and unmodified
    must still vouch for a young checkpoint's head, exactly as before this
    fix -- the gate must not reject legitimate archived material."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    signing_key = Ed25519PrivateKey.generate()
    verifying_key = signing_key.public_key().public_bytes_raw()

    full_chain = _chain(5)  # ts base 2026-06-10, ~92 days before `now` below
    checkpoint = _signed_checkpoint(
        signing_key, full_chain[3]["row_hash"], "2026-09-05T00:00:00.000Z"
    )
    now = dt.datetime(2026, 9, 10, tzinfo=dt.timezone.utc)  # checkpoint only 5 days old

    live_rows = full_chain[:2]
    bridge_row = dict(full_chain[3])  # genuinely archived, unmodified

    issues = verify_tier(
        live_rows,
        checkpoints=[checkpoint],
        bridge_rows=[bridge_row],
        keyring=_keyring(verifying_key),
        now=now,
    )
    assert not any(i["type"] == "checkpoint_head_missing" for i in issues)


def test_stale_checkpoint_is_flagged_when_the_checkpoint_job_has_stalled():
    """MEC-1634 finding 2: if the checkpoint job stops, or its rows are
    deleted, nothing else here would ever notice -- there is simply no
    recent checkpoint left to check reachability or a head against. This
    must be flagged on its own rather than only showing up once some other,
    checkpoint-dependent tamper happens to occur."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    signing_key = Ed25519PrivateKey.generate()
    verifying_key = signing_key.public_key().public_bytes_raw()

    rows = _chain(3)  # ts 12:00:00, 12:00:01, 12:00:02 on 2026-06-10
    checkpoint = _signed_checkpoint(signing_key, rows[1]["row_hash"], "2026-06-10T12:00:01.500Z")
    now = dt.datetime(2026, 6, 14, 12, 0, 0, tzinfo=dt.timezone.utc)  # checkpoint ~4 days stale

    issues = verify_tier(rows, checkpoints=[checkpoint], keyring=_keyring(verifying_key), now=now)
    assert any(i["type"] == "stale_checkpoint" for i in issues)


def test_stale_checkpoint_is_not_flagged_when_the_checkpoint_covers_all_rows():
    """No row is newer than the latest checkpoint, so there is nothing for
    the checkpoint job to have fallen behind on -- an old checkpoint alone
    must not be enough to flag staleness."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    signing_key = Ed25519PrivateKey.generate()
    verifying_key = signing_key.public_key().public_bytes_raw()

    rows = _chain(3)
    checkpoint = _signed_checkpoint(signing_key, rows[-1]["row_hash"], "2026-06-10T12:00:02.000Z")
    now = dt.datetime(2026, 6, 20, tzinfo=dt.timezone.utc)

    issues = verify_tier(rows, checkpoints=[checkpoint], keyring=_keyring(verifying_key), now=now)
    assert not any(i["type"] == "stale_checkpoint" for i in issues)


def test_checkpoint_count_regression_is_flagged_when_row_count_does_not_increase():
    """MEC-1634 finding 2: a legitimate checkpoint job's signed row_count is
    cumulative. A later, validly-signed checkpoint reporting a row_count no
    greater than an earlier one means checkpoint rows were deleted or the
    job restarted against a stale baseline -- a tamper invisible to every
    other check here, since it never touches ssdf.audit."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    signing_key = Ed25519PrivateKey.generate()
    verifying_key = signing_key.public_key().public_bytes_raw()

    rows = _chain(5)
    earlier = _signed_checkpoint(
        signing_key, rows[1]["row_hash"], "2026-06-10T00:00:00.000Z", row_count=10
    )
    later = _signed_checkpoint(
        signing_key, rows[3]["row_hash"], "2026-06-11T00:00:00.000Z", row_count=8
    )

    issues = verify_tier(
        rows,
        checkpoints=[earlier, later],
        keyring=_keyring(verifying_key),
        now=dt.datetime(2026, 6, 12, tzinfo=dt.timezone.utc),
    )
    assert any(
        i["type"] == "checkpoint_count_regression" and i["row_hash"] == later.head_row_hash
        for i in issues
    )


def test_checkpoint_count_regression_is_not_flagged_when_row_count_increases():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    signing_key = Ed25519PrivateKey.generate()
    verifying_key = signing_key.public_key().public_bytes_raw()

    rows = _chain(5)
    earlier = _signed_checkpoint(
        signing_key, rows[1]["row_hash"], "2026-06-10T00:00:00.000Z", row_count=8
    )
    later = _signed_checkpoint(
        signing_key, rows[3]["row_hash"], "2026-06-11T00:00:00.000Z", row_count=10
    )

    issues = verify_tier(
        rows,
        checkpoints=[earlier, later],
        keyring=_keyring(verifying_key),
        now=dt.datetime(2026, 6, 12, tzinfo=dt.timezone.utc),
    )
    assert not any(i["type"] == "checkpoint_count_regression" for i in issues)


def test_main_still_reports_a_chain_whose_rows_are_all_gone(monkeypatch):
    """A chain can have zero surviving rows in ssdf.audit (every row
    removed) while still holding a recent checkpoint. main() must still walk
    it via checkpoints_by_chain, not only via rows parsed from ssdf.audit --
    otherwise the chain has no key in `by_chain` at all and is silently
    absent from the run, and ``_checkpoint_head_issues`` never gets a chance
    to flag its checkpoint."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from ssdf_mcp_query import verify_audit

    signing_key = Ed25519PrivateKey.generate()
    verifying_key = signing_key.public_key().public_bytes_raw()

    full_chain = _chain(2)
    recent = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1)
    recent_ts = recent.strftime("%Y-%m-%dT%H:%M:%S.") + f"{recent.microsecond // 1000:03d}Z"
    checkpoint = _signed_checkpoint(signing_key, full_chain[-1]["row_hash"], recent_ts)

    class _Config:
        ch_audit_verify_password = "pw"
        ch_checkpoint_verify_key_paths = ("unused",)

    monkeypatch.setattr(verify_audit, "load_config", lambda: _Config())
    monkeypatch.setattr(verify_audit, "_fetch_rows", lambda config: [])
    monkeypatch.setattr(
        verify_audit, "_fetch_checkpoints", lambda config: {("sovereign", ""): [checkpoint]}
    )
    monkeypatch.setattr(verify_audit, "_fetch_evidence_rows", lambda config, now: {})
    monkeypatch.setattr(
        verify_audit, "_load_verifying_keyring", lambda config: _keyring(verifying_key)
    )

    assert verify_audit.main() == 1


def test_keyring_verifies_checkpoint_signed_by_either_ring_member():
    """MEC-1610: a checkpoint verifies against whichever ring member's
    locally computed fingerprint matches its key_id -- not just the first
    or "primary" one. Order in the ring must not matter."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key_a = Ed25519PrivateKey.generate()
    key_b = Ed25519PrivateKey.generate()
    ring = {
        **_keyring(key_a.public_key().public_bytes_raw()),
        **_keyring(key_b.public_key().public_bytes_raw()),
    }

    rows = _chain(3)
    checkpoint_signed_by_b = _signed_checkpoint(
        key_b, rows[1]["row_hash"], "2026-06-10T12:00:01.500Z"
    )

    issues = verify_tier(
        rows,
        checkpoints=[checkpoint_signed_by_b],
        keyring=ring,
        now=dt.datetime(2026, 6, 10, 12, 0, 2, tzinfo=dt.timezone.utc),
    )
    assert not any(i["type"] == "unverifiable_checkpoint" for i in issues)


def test_keyring_rejects_a_checkpoint_whose_key_id_matches_no_local_key():
    """A checkpoint naming a key_id that is not in the locally loaded
    keyring must fail closed (unverifiable_checkpoint), never silently pass
    just because *some* key in the ring happens to verify a signature it
    was never actually checked against."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    signing_key = Ed25519PrivateKey.generate()
    unrelated_key = Ed25519PrivateKey.generate()
    ring = _keyring(unrelated_key.public_key().public_bytes_raw())

    rows = _chain(3)
    checkpoint = _signed_checkpoint(signing_key, rows[1]["row_hash"], "2026-06-10T12:00:01.500Z")

    issues = verify_tier(
        rows,
        checkpoints=[checkpoint],
        keyring=ring,
        now=dt.datetime(2026, 6, 10, 12, 0, 2, tzinfo=dt.timezone.utc),
    )
    assert any(i["type"] == "unverifiable_checkpoint" for i in issues)


def test_key_rotation_overlap_window_verifies_both_old_and_new_checkpoints():
    """MEC-1610's core scenario: during the overlap window where both the
    retiring key and its replacement are present in the ring, checkpoints
    signed before AND after the rotation must both still verify -- the
    exact failure mode (every pre-rotation checkpoint going
    unverifiable_checkpoint for its full ~90-day lifetime) that motivated
    moving from a single verifying key to a keyring."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    old_key = Ed25519PrivateKey.generate()
    new_key = Ed25519PrivateKey.generate()

    full_chain = _chain(5)
    pre_rotation_checkpoint = _signed_checkpoint(
        old_key, full_chain[0]["row_hash"], "2026-06-11T00:00:00.000Z"
    )
    post_rotation_checkpoint = _signed_checkpoint(
        new_key, full_chain[2]["row_hash"], "2026-06-12T00:00:00.000Z", row_count=3
    )
    surviving = full_chain[3:]
    now = dt.datetime(2026, 9, 19, tzinfo=dt.timezone.utc)  # old enough to anchor on the genesis

    overlap_ring = {
        **_keyring(old_key.public_key().public_bytes_raw()),
        **_keyring(new_key.public_key().public_bytes_raw()),
    }

    issues = verify_tier(
        surviving,
        checkpoints=[pre_rotation_checkpoint, post_rotation_checkpoint],
        bridge_rows=full_chain[1:3],
        keyring=overlap_ring,
        now=now,
    )
    assert issues == []

    # Once the old key is retired from the ring (e.g. after its checkpoints
    # have left the ~90-day retention window), the pre-rotation checkpoint
    # alone would go unverifiable again -- but that is expected, not this
    # test's concern. Here we only assert the overlap window itself is
    # clean for both checkpoints.
    new_only_issues = verify_tier(
        surviving,
        checkpoints=[pre_rotation_checkpoint, post_rotation_checkpoint],
        bridge_rows=full_chain[1:3],
        keyring=_keyring(new_key.public_key().public_bytes_raw()),
        now=now,
    )
    assert any(i["type"] == "unverifiable_checkpoint" for i in new_only_issues)
