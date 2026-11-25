import asyncio
import os

os.environ.setdefault("CH_PASSWORD", "x")
os.environ.setdefault("MCP_AUTH_TOKEN", "t")


def _registered_tool_names(app):
    tools = asyncio.run(app.list_tools())
    return {t.name for t in tools}


def test_explain_access_tool_is_registered(monkeypatch):
    import ssdf_mcp_query.server as server

    class _Dummy:
        def __init__(self, *a, **k):
            pass

    monkeypatch.setattr(server, "ClickHouseClient", _Dummy)
    app = server.build_app()
    assert "explain_access" in _registered_tool_names(app)


def test_m12_sovereign_tools_registered(monkeypatch):
    import ssdf_mcp_query.server as server

    class _Dummy:
        def __init__(self, *a, **k):
            pass

    monkeypatch.setattr(server, "ClickHouseClient", _Dummy)
    names = _registered_tool_names(server.build_app())
    assert "configured_policies" in names
    assert "observed_by" in names


def test_m12_tools_absent_on_public(monkeypatch):
    import ssdf_mcp_query.server as server

    class _Dummy:
        def __init__(self, *a, **k):
            pass

    monkeypatch.setattr(server, "ClickHouseClient", _Dummy)
    names = _registered_tool_names(server.build_app(tier="public"))
    assert "configured_policies" not in names
    assert "observed_by" not in names


def test_policy_drift_sovereign_only(monkeypatch):
    import ssdf_mcp_query.server as server

    class _Dummy:
        def __init__(self, *a, **k):
            pass

    monkeypatch.setattr(server, "ClickHouseClient", _Dummy)
    assert "policy_drift" in _registered_tool_names(server.build_app())
    assert "policy_drift" not in _registered_tool_names(server.build_app(tier="public"))
