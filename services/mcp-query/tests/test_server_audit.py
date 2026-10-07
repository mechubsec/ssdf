import asyncio
import json

import pytest

from ssdf_mcp_query.tokenstore import digest_for
from ssdf_common.config import ConfigError
import os

os.environ.setdefault("CH_PASSWORD", "x")
os.environ.setdefault("MCP_AUTH_TOKEN", "t")

EXPECTED_TOOLS = {
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


def test_all_tools_registered_single_token(monkeypatch):
    import ssdf_mcp_query.server as server

    _patch_ch(monkeypatch, server)
    app = server.build_app()
    assert _names(app) == EXPECTED_TOOLS


def _write_tokens(tmp_path, payload):
    """Owner-only token file, as the loader now requires."""
    f = tmp_path / "tokens.json"
    f.write_text(json.dumps(payload))
    f.chmod(0o600)
    return f


def test_multi_principal_tokens_register(monkeypatch, tmp_path):
    import ssdf_mcp_query.server as server

    f = _write_tokens(
        tmp_path,
        {
            digest_for("tok-a"): {"principal": "triage-agent", "allowed_tools": ["query_flows"]},
            digest_for("tok-b"): {"principal": "admin-agent"},
        },
    )
    monkeypatch.setenv("MCP_TOKENS_FILE", str(f))
    _patch_ch(monkeypatch, server)
    app = server.build_app()
    assert _names(app) == EXPECTED_TOOLS


def test_build_app_fails_closed_when_audit_required_without_password(monkeypatch):
    """M16f: MCP_AUDIT_REQUIRED=1 with no CH_AUDIT_PASSWORD must refuse to
    start the server rather than silently run with audit disabled. Only
    ClickHouseClient is stubbed here -- make_ch_auditor runs for real, since
    that is exactly the fail-closed path under test."""
    import ssdf_mcp_query.server as server

    class _Dummy:
        def __init__(self, *a, **k):
            pass

    monkeypatch.setattr(server, "ClickHouseClient", _Dummy)
    monkeypatch.setenv("MCP_AUDIT_REQUIRED", "1")
    monkeypatch.delenv("CH_AUDIT_PASSWORD", raising=False)
    with pytest.raises(ConfigError):
        server.build_app()


def test_not_after_lands_in_verifier_claims(monkeypatch, tmp_path):
    import ssdf_mcp_query.server as server

    f = _write_tokens(
        tmp_path,
        {
            digest_for("tok-exp"): {
                "principal": "expiring",
                "not_after": "2026-09-09T12:00:00+00:00",
                "local_only": True,
            },
            digest_for("tok-forever"): {"principal": "forever", "local_only": True},
        },
    )
    monkeypatch.setenv("MCP_TOKENS_FILE", str(f))
    _patch_ch(monkeypatch, server)
    captured = {}
    real_verifier = server.DigestTokenVerifier

    def _spy(tokens):
        captured.update(tokens)
        return real_verifier(tokens)

    monkeypatch.setattr(server, "DigestTokenVerifier", _spy)
    server.build_app()
    # The verifier is handed DIGESTS, never the tokens themselves.
    assert captured[digest_for("tok-exp")]["not_after"] == "2026-09-09T12:00:00+00:00"
    assert "not_after" not in captured[digest_for("tok-forever")]
    assert not any(k.startswith("tok-") for k in captured), "a plaintext token reached the verifier"


def test_mask_error_details_hides_exception_detail(monkeypatch):
    """F6: build_app() must wire FastMCP(..., mask_error_details=True) so an
    uncaught tool exception never reaches the model as tool-call output --
    only ssdf.audit (via wrapper.audited_tool's finally-block write) gets the
    real detail. Exercised end-to-end through an in-memory fastmcp.Client
    against the real built app, not just the FastMCP constructor call."""
    import ssdf_mcp_query.server as server
    from fastmcp import Client
    from fastmcp.exceptions import ToolError

    _patch_ch(monkeypatch, server)

    secret_detail = "clickhouse: connection refused at 192.0.2.10:8443 password=hunter2"

    def _boom(self, **kwargs):
        raise RuntimeError(secret_detail)

    # query_flows has no internal try/except around the ClickHouse call in
    # Tools (unlike describe_schema/run_sql, which scrub upstream errors
    # themselves) -- patch it directly so the exception reaches FastMCP
    # unguarded, the same as a genuine unexpected bug would.
    monkeypatch.setattr(server.Tools, "query_flows", _boom)

    app = server.build_app()

    async def _call():
        async with Client(app) as client:
            return await client.call_tool("query_flows", {})

    with pytest.raises(ToolError) as excinfo:
        asyncio.run(_call())

    assert str(excinfo.value) == "Error calling tool 'query_flows'"
    assert "hunter2" not in str(excinfo.value)
    assert "RuntimeError" not in str(excinfo.value)
