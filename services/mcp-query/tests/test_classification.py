import json
import pytest
from ssdf_mcp_query.classification import (
    classes_for_tool,
    load_classification,
    public_tool_names,
    is_tool_shareable,
    PUBLIC_EXCLUDED_TOOLS,
    TOOL_DATA_CLASSES,
)
from ssdf_mcp_query.config import ConfigError

EXPECTED = {
    "query_flows": {"security_log"},
    "describe_schema": {"security_log"},
    "top_talkers": {"security_log"},
    "zone_matrix": {"security_log"},
    "run_sql": {"security_log"},
    "get_entity": {"identity"},
    "locate": {"topology"},
    "neighbors": {"topology"},
    "find_path": {"topology"},
    "enforcement_points": {"topology", "firewall_config"},
    "topology_snapshot": {"topology"},
    "explain_access": {"security_log", "topology", "identity", "firewall_config"},
    "configured_policies": {"firewall_config"},
    "observed_by": {"security_log"},
    "ingest_status": {"security_log"},
    "fabric_status": {"security_log"},
    "lab_topology_snapshot": {"topology"},
    "recent_alerts": {"security_log"},
    "metric_timeseries": {"metrics"},
    "top_series": {"metrics"},
    "entity_metric_timeseries": {"metrics"},
    "reidentify": {"identity"},
    "rule_history": {"firewall_config"},
    "rule_usage": {"security_log", "firewall_config"},
    "unused_rules": {"security_log", "firewall_config"},
    "explain_rule": {"security_log", "firewall_config"},
    "change_impact": {"security_log", "firewall_config"},
}


def test_tool_class_map_matches_spec():
    assert set(TOOL_DATA_CLASSES) == set(EXPECTED)
    for tool, classes in EXPECTED.items():
        assert set(classes_for_tool(tool)) == classes


def test_unknown_tool_returns_empty():
    assert classes_for_tool("does_not_exist") == frozenset()


def test_defaults_all_sovereign():
    c = load_classification(None)
    for cls in ("security_log", "firewall_config", "topology", "identity"):
        assert c.label_for_class(cls) == "sovereign"


def test_override_topology_shareable(tmp_path):
    f = tmp_path / "cls.json"
    f.write_text(json.dumps({"topology": "shareable"}))
    c = load_classification(str(f))
    assert c.label_for_class("topology") == "shareable"
    assert c.label_for_class("identity") == "sovereign"


def test_override_identity_sovereign_is_noop(tmp_path):
    f = tmp_path / "cls.json"
    f.write_text(json.dumps({"identity": "sovereign"}))
    assert load_classification(str(f)).label_for_class("identity") == "sovereign"


@pytest.mark.parametrize("cls", ["security_log", "firewall_config"])
def test_reject_non_configurable_override(tmp_path, cls):
    f = tmp_path / "cls.json"
    f.write_text(json.dumps({cls: "shareable"}))
    with pytest.raises(ConfigError):
        load_classification(str(f))


def test_reject_unknown_class(tmp_path):
    f = tmp_path / "cls.json"
    f.write_text(json.dumps({"bogus": "shareable"}))
    with pytest.raises(ConfigError):
        load_classification(str(f))


def test_reject_bad_value(tmp_path):
    f = tmp_path / "cls.json"
    f.write_text(json.dumps({"topology": "public"}))
    with pytest.raises(ConfigError):
        load_classification(str(f))


def test_reject_non_object_json(tmp_path):
    f = tmp_path / "cls.json"
    f.write_text(json.dumps(["topology"]))
    with pytest.raises(ConfigError):
        load_classification(str(f))


def test_label_for_unknown_class_raises():
    with pytest.raises(ConfigError):
        load_classification(None).label_for_class("bogus")


def test_missing_file_raises(tmp_path):
    missing = tmp_path / "does-not-exist.json"
    with pytest.raises(ConfigError):
        load_classification(str(missing))


ALL_TOOLS = [
    "query_flows",
    "describe_schema",
    "top_talkers",
    "run_sql",
    "get_entity",
    "locate",
    "neighbors",
    "find_path",
    "enforcement_points",
    "topology_snapshot",
    "explain_access",
]


def _classification(**overrides):
    """Build a Classification with the given class->label overrides (rest sovereign)."""
    import json
    import tempfile
    import os

    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as handle:
        json.dump(overrides, handle)
    try:
        return load_classification(path)
    finally:
        os.unlink(path)


def test_run_sql_is_excluded_from_public():
    assert "run_sql" in PUBLIC_EXCLUDED_TOOLS


def test_no_shareable_classes_yields_empty_public_set():
    classification = _classification()  # all sovereign
    assert public_tool_names(classification, ALL_TOOLS) == []


def test_topology_flip_exposes_four_topology_tools():
    classification = _classification(topology="shareable")
    assert public_tool_names(classification, ALL_TOOLS) == [
        "locate",
        "neighbors",
        "find_path",
        "topology_snapshot",
    ]


def test_identity_flip_exposes_get_entity_only():
    classification = _classification(identity="shareable")
    assert public_tool_names(classification, ALL_TOOLS) == ["get_entity"]


def test_both_flips_expose_five_tools_and_not_run_sql():
    classification = _classification(topology="shareable", identity="shareable")
    selected = public_tool_names(classification, ALL_TOOLS)
    assert selected == [
        "get_entity",
        "locate",
        "neighbors",
        "find_path",
        "topology_snapshot",
    ]
    assert "run_sql" not in selected
    # enforcement_points + explain_access carry locked classes -> never public
    assert "enforcement_points" not in selected
    assert "explain_access" not in selected


def test_is_tool_shareable_false_for_unknown_tool():
    classification = _classification(topology="shareable", identity="shareable")
    assert is_tool_shareable(classification, "made_up_tool") is False


def test_new_m12_tools_are_classified_and_never_shareable():
    from ssdf_mcp_query.classification import classes_for_tool, is_tool_shareable, Classification

    assert classes_for_tool("configured_policies") == frozenset({"firewall_config"})
    assert classes_for_tool("observed_by") == frozenset({"security_log"})

    # even with topology+identity flipped shareable (the public config), neither
    # tool is shareable: firewall_config + security_log are not configurable.
    cls = Classification(
        labels={
            "security_log": "sovereign",
            "firewall_config": "sovereign",
            "topology": "shareable",
            "identity": "shareable",
        }
    )
    assert is_tool_shareable(cls, "configured_policies") is False
    assert is_tool_shareable(cls, "observed_by") is False


def test_metrics_class_is_configurable_and_tools_classed():
    from ssdf_mcp_query.classification import (
        DATA_CLASSES,
        CONFIGURABLE_CLASSES,
        classes_for_tool,
    )

    assert "metrics" in DATA_CLASSES
    assert "metrics" in CONFIGURABLE_CLASSES
    assert classes_for_tool("metric_timeseries") == frozenset({"metrics"})
    assert classes_for_tool("top_series") == frozenset({"metrics"})
    assert classes_for_tool("entity_metric_timeseries") == frozenset({"metrics"})
    assert classes_for_tool("reidentify") == frozenset({"identity"})


def test_metrics_can_be_flipped_shareable(tmp_path):
    import json
    from ssdf_mcp_query.classification import load_classification, is_tool_shareable

    path = tmp_path / "c.json"
    path.write_text(json.dumps({"metrics": "shareable"}))
    c = load_classification(str(path))
    assert is_tool_shareable(c, "metric_timeseries") is True
    assert is_tool_shareable(c, "reidentify") is False  # identity stays sovereign


def test_zone_matrix_is_security_log_and_never_shareable():
    assert TOOL_DATA_CLASSES["zone_matrix"] == frozenset({"security_log"})
    assert classes_for_tool("zone_matrix") == frozenset({"security_log"})
    # security_log is not configurable, so even with every configurable class
    # flipped shareable the tool stays sovereign-only.
    everything_shareable = _classification(
        topology="shareable", identity="shareable", metrics="shareable"
    )
    assert is_tool_shareable(everything_shareable, "zone_matrix") is False
    assert "zone_matrix" not in public_tool_names(everything_shareable, ["zone_matrix"])
