"""change_impact (MEC-1640, task C of MEC-570): read-only differential first-match
replay. Evaluates historical flows against the current rulebase P and a proposed
P' and reports which flows' verdicts change.

Pure, deterministic, no device or ClickHouse I/O in this package -- see
docs/mcp-986 "change-impact-scope" for the algorithm this implements. The
house rule applies: this package decides nothing by inference, only by
explicit three-valued logic over the collected config and logs. Any narration
built on top of its output stays at `explain_rule` depth: string formatting
over cited numbers, never a judgement the data doesn't support.
"""

from .kleene import K_FALSE, K_TRUE, K_UNKNOWN, Kleene3, k_and, k_not, k_or
from .delta import (
    Delta,
    DeltaError,
    apply_delta,
    apply_junos_set_delta,
    apply_junos_text_delta,
    parse_json_delta,
    validate_security_policies_only,
)
from .rulemodel import CompiledRule, compile_rulebase
from .diff import DiffResult, diff_rulebases
from .flowtuple import FlowTuple, effective_tuple
from .evaluator import (
    Classification,
    EvaluatedTuple,
    Verdict,
    classify,
    config_only_precheck,
    evaluate_candidates,
    firstmatch3,
)
from .calibration import CalibrationResult, apply_calibration_gate, calibration_gate
from .pipeline import evaluate_change_impact
from .report import (
    AMBIGUOUS_RULE_NAME,
    CONFIG_ONLY_NO_IMPACT,
    NO_SESSIONS_OBSERVED,
    build_calibration_section,
    build_deny_side_blindness,
    build_report,
    build_rule_section,
    content_hash,
)

__all__ = [
    "K_FALSE",
    "K_TRUE",
    "K_UNKNOWN",
    "Kleene3",
    "k_and",
    "k_or",
    "k_not",
    "DeltaError",
    "Delta",
    "apply_delta",
    "apply_junos_set_delta",
    "apply_junos_text_delta",
    "parse_json_delta",
    "validate_security_policies_only",
    "CompiledRule",
    "compile_rulebase",
    "DiffResult",
    "diff_rulebases",
    "FlowTuple",
    "effective_tuple",
    "Classification",
    "EvaluatedTuple",
    "Verdict",
    "classify",
    "config_only_precheck",
    "evaluate_candidates",
    "firstmatch3",
    "CalibrationResult",
    "calibration_gate",
    "apply_calibration_gate",
    "evaluate_change_impact",
    "build_report",
    "build_rule_section",
    "build_calibration_section",
    "build_deny_side_blindness",
    "content_hash",
    "CONFIG_ONLY_NO_IMPACT",
    "NO_SESSIONS_OBSERVED",
    "AMBIGUOUS_RULE_NAME",
]
