"""Data-classification taxonomy (M7a).

Pure module, secure-by-default: every class defaults to ``sovereign``; only the
two configurable classes (``topology``, ``identity``) may be flipped to
``shareable`` via the optional JSON config. M7a only *labels* — it never gates.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from .config import ConfigError

DATA_CLASSES: frozenset[str] = frozenset(
    {"security_log", "firewall_config", "topology", "identity", "metrics"}
)
CONFIGURABLE_CLASSES: frozenset[str] = frozenset({"topology", "identity", "metrics"})
LABELS: frozenset[str] = frozenset({"sovereign", "shareable"})

# Single source of truth: the data classes each tool's output can contain.
TOOL_DATA_CLASSES: dict[str, frozenset[str]] = {
    "query_flows": frozenset({"security_log"}),
    "describe_schema": frozenset({"security_log"}),
    "top_talkers": frozenset({"security_log"}),
    "zone_matrix": frozenset({"security_log"}),
    "run_sql": frozenset({"security_log"}),
    "get_entity": frozenset({"identity"}),
    "locate": frozenset({"topology"}),
    "neighbors": frozenset({"topology"}),
    "find_path": frozenset({"topology"}),
    "enforcement_points": frozenset({"topology", "firewall_config"}),
    "topology_snapshot": frozenset({"topology"}),
    "explain_access": frozenset({"security_log", "topology", "identity", "firewall_config"}),
    "configured_policies": frozenset({"firewall_config"}),
    "observed_by": frozenset({"security_log"}),
    "ingest_status": frozenset({"security_log"}),
    "fabric_status": frozenset({"security_log"}),
    "lab_topology_snapshot": frozenset({"topology"}),
    "recent_alerts": frozenset({"security_log"}),
    "metric_timeseries": frozenset({"metrics"}),
    "top_series": frozenset({"metrics"}),
    "entity_metric_timeseries": frozenset({"metrics"}),
    "reidentify": frozenset({"identity"}),
    "rule_history": frozenset({"firewall_config"}),
    "rule_usage": frozenset({"security_log", "firewall_config"}),
    "unused_rules": frozenset({"security_log", "firewall_config"}),
    "explain_rule": frozenset({"security_log", "firewall_config"}),
    "change_impact": frozenset({"security_log", "firewall_config"}),
}


@dataclass(frozen=True)
class Classification:
    """Resolved per-class sovereignty labels (class -> 'sovereign'|'shareable')."""

    labels: dict[str, str]

    def label_for_class(self, data_class: str) -> str:
        """Return the sovereignty label for a known data class."""
        if data_class not in DATA_CLASSES:
            raise ConfigError(f"unknown data class: {data_class}")
        return self.labels[data_class]


def classes_for_tool(tool_name: str) -> frozenset[str]:
    """Return the set of data classes a tool's output can contain (empty if unknown)."""
    return TOOL_DATA_CLASSES.get(tool_name, frozenset())


def load_classification(path: str | None = None) -> Classification:
    """Load classification overrides from an optional JSON file (secure-by-default).

    ``path`` falls back to env ``MCP_CLASSIFICATION_FILE`` when ``None``. Missing
    keys default to ``sovereign``. Raises ``ConfigError`` on any invalid override.
    """
    labels = {data_class: "sovereign" for data_class in DATA_CLASSES}
    resolved = path if path is not None else os.environ.get("MCP_CLASSIFICATION_FILE")
    if not resolved:
        return Classification(labels=labels)
    try:
        raw = Path(resolved).read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read classification file '{resolved}': {exc}") from exc
    try:
        overrides = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"invalid classification JSON: {exc}") from exc
    if not isinstance(overrides, dict):
        raise ConfigError("classification config must be a JSON object")
    for data_class, value in overrides.items():
        if data_class not in DATA_CLASSES:
            raise ConfigError(f"unknown data class: {data_class}")
        if data_class not in CONFIGURABLE_CLASSES:
            raise ConfigError(f"class '{data_class}' is not configurable (always sovereign)")
        if value not in LABELS:
            raise ConfigError(f"invalid label '{value}' for class '{data_class}'")
        labels[data_class] = value
    return Classification(labels=labels)


# Tools structurally barred from the public server regardless of classification
# (defense in depth: arbitrary SQL must never live on the public process).
PUBLIC_EXCLUDED_TOOLS: frozenset[str] = frozenset({"run_sql"})


def is_tool_shareable(classification: Classification, tool_name: str) -> bool:
    """True iff every class the tool returns is 'shareable' and it is not excluded.

    Unknown tools (no declared classes) and hard-excluded tools are never shareable.
    """
    if tool_name in PUBLIC_EXCLUDED_TOOLS:
        return False
    classes = classes_for_tool(tool_name)
    if not classes:
        return False
    return all(classification.label_for_class(cls) == "shareable" for cls in classes)


def public_tool_names(classification: Classification, candidates: list[str]) -> list[str]:
    """Return, in input order, the candidate tools exposable on the public server."""
    return [name for name in candidates if is_tool_shareable(classification, name)]
