from types import SimpleNamespace
import ssdf_mcp_query.auth as auth


def _fake_token(claims):
    return SimpleNamespace(claims=claims)


def test_principal_and_allowed_tools(monkeypatch):
    monkeypatch.setattr(
        auth,
        "get_access_token",
        lambda: _fake_token({"principal": "triage-agent", "allowed_tools": ["query_flows"]}),
    )
    principal, allowed = auth.current_caller()
    assert principal == "triage-agent"
    assert allowed == frozenset({"query_flows"})


def test_allowed_tools_absent_means_none(monkeypatch):
    monkeypatch.setattr(auth, "get_access_token", lambda: _fake_token({"principal": "admin-agent"}))
    principal, allowed = auth.current_caller()
    assert principal == "admin-agent"
    assert allowed is None


def test_falls_back_to_sub(monkeypatch):
    monkeypatch.setattr(auth, "get_access_token", lambda: _fake_token({"sub": "agent"}))
    assert auth.current_caller() == ("agent", None)


def test_no_token_returns_unknown(monkeypatch):
    monkeypatch.setattr(auth, "get_access_token", lambda: None)
    assert auth.current_caller() == ("unknown", None)


def test_claims_with_not_after(monkeypatch):
    import datetime as dt

    monkeypatch.setattr(
        auth,
        "get_access_token",
        lambda: _fake_token({"principal": "p", "not_after": "2026-09-09T12:00:00+00:00"}),
    )
    principal, allowed, not_after = auth.current_caller_claims()
    assert principal == "p"
    assert allowed is None
    assert not_after == dt.datetime(2026, 9, 9, 12, 0, 0, tzinfo=dt.timezone.utc)


def test_claims_naive_not_after_is_utc(monkeypatch):
    import datetime as dt

    monkeypatch.setattr(
        auth,
        "get_access_token",
        lambda: _fake_token({"principal": "p", "not_after": "2026-09-09T12:00:00"}),
    )
    _, _, not_after = auth.current_caller_claims()
    assert not_after == dt.datetime(2026, 9, 9, 12, 0, 0, tzinfo=dt.timezone.utc)


def test_claims_without_not_after(monkeypatch):
    monkeypatch.setattr(
        auth,
        "get_access_token",
        lambda: _fake_token({"principal": "p", "allowed_tools": ["locate"]}),
    )
    principal, allowed, not_after = auth.current_caller_claims()
    assert (principal, allowed) == ("p", frozenset({"locate"}))
    assert not_after is None


def test_claims_malformed_not_after_fails_closed(monkeypatch):
    """An unparseable not_after claim must read as already expired (fail closed)."""
    import datetime as dt

    monkeypatch.setattr(
        auth, "get_access_token", lambda: _fake_token({"principal": "p", "not_after": "garbage"})
    )
    _, _, not_after = auth.current_caller_claims()
    assert not_after is not None
    assert not_after <= dt.datetime.now(dt.timezone.utc)


def test_identity_returns_own_fields_only(monkeypatch):
    monkeypatch.setattr(
        auth,
        "get_access_token",
        lambda: _fake_token(
            {
                "principal": "bot",
                "allowed_tools": ["query_flows"],
                "created_at": "2026-08-01T00:00:00+00:00",
                "not_after": "2026-11-01T00:00:00",
                "local_only": True,
                "digest": "sha256:abc",
            }
        ),
    )
    assert auth.current_caller_identity() == {
        "principal": "bot",
        "created_at": "2026-08-01T00:00:00+00:00",
        "expires_at": "2026-11-01T00:00:00+00:00",
        "local_only": True,
    }


def test_identity_nulls_when_absent(monkeypatch):
    monkeypatch.setattr(auth, "get_access_token", lambda: _fake_token({"principal": "p"}))
    assert auth.current_caller_identity() == {
        "principal": "p",
        "created_at": None,
        "expires_at": None,
        "local_only": False,
    }
