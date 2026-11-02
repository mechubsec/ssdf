from ssdf_mcp_query.mint_token import build_entry


def test_build_entry_omits_local_only_by_default():
    _, entry = build_entry("p", None, None)
    (fields,) = entry.values()
    assert "local_only" not in fields


def test_build_entry_local_only_flag_sets_true():
    _, entry = build_entry("p", None, None, local_only=True)
    (fields,) = entry.values()
    assert fields["local_only"] is True


def test_build_entry_writes_created_at_matching_expiry_base():
    import datetime as dt

    _, entry = build_entry("p", None, 90)
    (fields,) = entry.values()
    created = dt.datetime.fromisoformat(fields["created_at"])
    assert created.tzinfo is not None and created.microsecond == 0
    assert dt.datetime.fromisoformat(fields["not_after"]) - created == dt.timedelta(days=90)
