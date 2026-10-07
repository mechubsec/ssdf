import asyncio
import json
import os

os.environ.setdefault("CH_PASSWORD", "x")
os.environ.setdefault("MCP_AUTH_TOKEN", "t")

SOVEREIGN_TOOLS = {
    "query_flows",
    "describe_schema",
    "top_talkers",
    "zone_matrix",
    "run_sql",
    "get_entity",
    "locate",
    "neighbors",
    "find_path",
    "enforcement_points",
    "topology_snapshot",
    "explain_access",
    "configured_policies",
    "observed_by",
    "ingest_status",
    "fabric_status",
    "lab_topology_snapshot",
    "recent_alerts",
    "metric_timeseries",
    "top_series",
    "entity_metric_timeseries",
    "reidentify",
    "rule_history",
    "rule_usage",
    "unused_rules",
    "explain_rule",
    "change_impact",
}


def _names(app):
    return {t.name for t in asyncio.run(app.list_tools())}


def _patch_ch(monkeypatch, server):
    class _Dummy:
        def __init__(self, *a, **k):
            pass

    monkeypatch.setattr(server, "ClickHouseClient", _Dummy)
    monkeypatch.setattr(
        server, "make_ch_auditor", lambda config, tier="sovereign": server.Auditor(lambda row: None)
    )


def _classification_file(tmp_path, **overrides):
    path = tmp_path / "classification.json"
    path.write_text(json.dumps(overrides))
    return str(path)


def test_public_build_both_classes_exposes_five_tools(monkeypatch, tmp_path):
    import ssdf_mcp_query.server as server

    _patch_ch(monkeypatch, server)
    monkeypatch.setenv(
        "MCP_CLASSIFICATION_FILE",
        _classification_file(tmp_path, topology="shareable", identity="shareable"),
    )
    app = server.build_app(tier="public")
    assert _names(app) == {
        "get_entity",
        "locate",
        "neighbors",
        "find_path",
        "topology_snapshot",
    }


def test_public_build_topology_only(monkeypatch, tmp_path):
    import ssdf_mcp_query.server as server

    _patch_ch(monkeypatch, server)
    monkeypatch.setenv(
        "MCP_CLASSIFICATION_FILE", _classification_file(tmp_path, topology="shareable")
    )
    app = server.build_app(tier="public")
    assert _names(app) == {"locate", "neighbors", "find_path", "topology_snapshot"}
    assert "get_entity" not in _names(app)


def test_public_build_zero_tools_warns(monkeypatch, tmp_path, capsys):
    import ssdf_mcp_query.server as server

    _patch_ch(monkeypatch, server)
    # no MCP_CLASSIFICATION_FILE -> everything sovereign -> zero public tools
    monkeypatch.delenv("MCP_CLASSIFICATION_FILE", raising=False)
    app = server.build_app(tier="public")
    assert _names(app) == set()
    assert "no shareable classes" in capsys.readouterr().err


def test_public_build_never_exposes_run_sql_or_security_tools(monkeypatch, tmp_path):
    import ssdf_mcp_query.server as server

    _patch_ch(monkeypatch, server)
    monkeypatch.setenv(
        "MCP_CLASSIFICATION_FILE",
        _classification_file(tmp_path, topology="shareable", identity="shareable"),
    )
    names = _names(server.build_app(tier="public"))
    for forbidden in (
        "run_sql",
        "query_flows",
        "describe_schema",
        "top_talkers",
        "zone_matrix",
        "enforcement_points",
        "explain_access",
    ):
        assert forbidden not in names


def test_sovereign_build_unchanged(monkeypatch):
    import ssdf_mcp_query.server as server

    _patch_ch(monkeypatch, server)
    app = server.build_app()  # default tier="sovereign"
    assert _names(app) == SOVEREIGN_TOOLS


def test_public_build_does_not_construct_entity_store(monkeypatch, tmp_path):
    """L5: the public tier never registers entity tools, so the sovereign-only
    ClickHouseEntityStore/AccessTools must not even be constructed."""
    import ssdf_mcp_query.server as server

    _patch_ch(monkeypatch, server)
    monkeypatch.setenv(
        "MCP_CLASSIFICATION_FILE",
        _classification_file(tmp_path, topology="shareable", identity="shareable"),
    )
    constructed = {"entity_store": 0, "access": 0}

    class _EntitySpy:
        def __init__(self, *a, **k):
            constructed["entity_store"] += 1

    class _AccessSpy:
        def __init__(self, *a, **k):
            constructed["access"] += 1

    monkeypatch.setattr(server, "ClickHouseEntityStore", _EntitySpy)
    monkeypatch.setattr(server, "AccessTools", _AccessSpy)
    app = server.build_app(tier="public")
    assert constructed == {"entity_store": 0, "access": 0}
    # tool surface unchanged by the gating
    assert _names(app) == {
        "get_entity",
        "locate",
        "neighbors",
        "find_path",
        "topology_snapshot",
    }


def test_sovereign_build_constructs_entity_store(monkeypatch):
    import ssdf_mcp_query.server as server

    _patch_ch(monkeypatch, server)
    constructed = {"entity_store": 0}
    real_store = server.ClickHouseEntityStore

    def _spy(*a, **k):
        constructed["entity_store"] += 1
        return real_store(*a, **k)

    monkeypatch.setattr(server, "ClickHouseEntityStore", _spy)
    app = server.build_app()
    assert constructed["entity_store"] == 1
    assert _names(app) == SOVEREIGN_TOOLS


def test_public_build_uses_public_schema(monkeypatch, tmp_path):
    import ssdf_mcp_query.server as server

    _patch_ch(monkeypatch, server)
    monkeypatch.setenv(
        "MCP_CLASSIFICATION_FILE",
        _classification_file(tmp_path, topology="shareable", identity="shareable"),
    )
    captured = {}
    real_store = server.ClickHouseGraphStore

    def _spy(ch_client, tenant="t_main", schema="ssdf"):
        captured["schema"] = schema
        return real_store(ch_client, tenant=tenant, schema=schema)

    monkeypatch.setattr(server, "ClickHouseGraphStore", _spy)
    server.build_app(tier="public")
    assert captured["schema"] == "ssdf_public"


def test_public_build_metrics_config_exposes_only_metrics(monkeypatch, tmp_path):
    import ssdf_mcp_query.server as server

    _patch_ch(monkeypatch, server)
    monkeypatch.setenv(
        "MCP_CLASSIFICATION_FILE", _classification_file(tmp_path, metrics="shareable")
    )
    app = server.build_app(tier="public")
    assert _names(app) == {
        "metric_timeseries",
        "top_series",
        "entity_metric_timeseries",
    }
    assert "reidentify" not in _names(app)  # sovereign-only, never a public candidate


def test_public_metrics_example_config_is_metrics_only(monkeypatch):
    import ssdf_mcp_query.server as server

    _patch_ch(monkeypatch, server)
    monkeypatch.setenv(
        "MCP_CLASSIFICATION_FILE", "infra/classification.public.metrics.example.json"
    )
    app = server.build_app(tier="public")
    assert _names(app) == {
        "metric_timeseries",
        "top_series",
        "entity_metric_timeseries",
    }


def test_zone_matrix_not_on_public_tier(monkeypatch, tmp_path):
    import ssdf_mcp_query.server as server

    _patch_ch(monkeypatch, server)
    monkeypatch.setenv(
        "MCP_CLASSIFICATION_FILE",
        _classification_file(
            tmp_path, topology="shareable", identity="shareable", metrics="shareable"
        ),
    )
    assert "zone_matrix" not in _names(server.build_app(tier="public"))


def test_zone_matrix_on_sovereign_tier(monkeypatch):
    import ssdf_mcp_query.server as server

    _patch_ch(monkeypatch, server)
    assert "zone_matrix" in _names(server.build_app(tier="sovereign"))
