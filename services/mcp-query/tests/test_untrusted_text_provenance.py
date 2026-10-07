"""Every registered tool whose response can carry UntrustedText-wrapped fields
(MEC-568) must say so in its own model-facing description -- a provenance note
elsewhere in the module does not help the model unless the tool's own
docstring, which FastMCP surfaces verbatim via functools.wraps, carries it."""

import asyncio
import os

os.environ.setdefault("CH_PASSWORD", "x")
os.environ.setdefault("MCP_AUTH_TOKEN", "t")

import ssdf_mcp_query.server as server

_PROVENANCE_MARKER = "not instructions"

# Tools whose response shape includes at least one UntrustedText.to_response()
# or raw-row-with-log-derived-column output (see untrusted_text.py, alerts.py,
# access_tools.py, tools.py's _wrap_untrusted_columns, run_sql).
_UNTRUSTED_BEARING_TOOLS = {
    "query_flows",
    "run_sql",
    "explain_access",
    "recent_alerts",
}


def _descriptions(monkeypatch, tier="sovereign"):
    class _Dummy:
        def __init__(self, *a, **k):
            pass

    monkeypatch.setattr(server, "ClickHouseClient", _Dummy)
    app = server.build_app(tier=tier)
    tools = asyncio.run(app.list_tools())
    return {t.name: (t.description or "") for t in tools}


def test_untrusted_bearing_tools_carry_a_provenance_note(monkeypatch):
    descriptions = _descriptions(monkeypatch)
    missing = [
        name
        for name in _UNTRUSTED_BEARING_TOOLS
        if name in descriptions and _PROVENANCE_MARKER not in descriptions[name]
    ]
    assert missing == [], (
        f"tool(s) {missing} return log-derived text without a provenance note "
        "in their own model-facing description"
    )
