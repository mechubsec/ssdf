"""Calibration gate (doc §1.4, "falsifiability hook for the whole feature").

Per zone-pair, agreement between the evaluator's P-verdict and the logged
`rule_name` is computed over candidate sessions whose first-seen is at or
after `cutoff` (the latest relevant `policy_versions.valid_from` across every
rule in the changed set -- a single device-level value, not looked up per
zone-pair: a changed rule's own zone pair can be `("any", "any")`, but the
candidate pull's actual flow rows carry the flow's real, specific zone pair,
so a per-zone-pair lookup would miss and silently treat every session as
having no cutoff at all -- older logs legitimately came from a different
rulebase, see doc §1.4). If
agreement is below threshold, or the post-cutoff sample is too small, every
verdict touching that zone-pair is reported `unknown: model does not
reproduce device behaviour`, never a guess -- this is the one check standing
between a bug anywhere upstream (object resolution, NAT handling, an
unmodelled match clause) and a report telling someone it's safe to delete a
rule.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .evaluator import EvaluatedTuple

DEFAULT_THRESHOLD = 0.99
DEFAULT_MIN_SAMPLE = 100
MAX_MISMATCH_EXAMPLES = 10


@dataclass(frozen=True)
class CalibrationResult:
    zone_pair: tuple[str, str]
    sample_sessions: int
    agreeing_sessions: int
    status: str  # "ok" | "below_threshold" | "insufficient_sample"
    threshold: float
    min_sample: int
    mismatch_examples: tuple[dict, ...] = field(default_factory=tuple)

    @property
    def agreement(self) -> float | None:
        if self.sample_sessions == 0:
            return None
        return self.agreeing_sessions / self.sample_sessions

    @property
    def trusted(self) -> bool:
        return self.status == "ok"


def _zone_pair(evaluated: EvaluatedTuple) -> tuple[str, str]:
    return (evaluated.flow.ingress_zone, evaluated.flow.egress_zone)


def _after_cutoff(evaluated: EvaluatedTuple, cutoff: str | None) -> bool:
    if cutoff is None:
        return True
    if evaluated.first_seen is None:
        return False  # can't prove it's post-cutoff; exclude rather than assume
    return evaluated.first_seen >= cutoff


def calibration_gate(
    evaluated: list[EvaluatedTuple],
    cutoff: str | None = None,
    threshold: float = DEFAULT_THRESHOLD,
    min_sample: int = DEFAULT_MIN_SAMPLE,
) -> dict[tuple[str, str], CalibrationResult]:
    by_zone: dict[tuple[str, str], list[EvaluatedTuple]] = {}
    for item in evaluated:
        by_zone.setdefault(_zone_pair(item), []).append(item)

    results: dict[tuple[str, str], CalibrationResult] = {}
    for zone_pair, items in by_zone.items():
        sample = 0
        agree = 0
        mismatches: list[dict] = []
        for item in items:
            if not _after_cutoff(item, cutoff):
                continue
            sample += item.sessions
            is_agreement = (
                item.before.status == "match" and item.before.rule_name in item.logged_rules
            )
            if is_agreement:
                agree += item.sessions
            elif len(mismatches) < MAX_MISMATCH_EXAMPLES:
                mismatches.append(
                    {
                        "src_ip": item.flow.src_ip,
                        "dst_ip": item.flow.dst_ip,
                        "transport": item.flow.transport,
                        "dst_port": item.flow.dst_port,
                        "evaluator_verdict": item.before.rule_name
                        or f"unknown({item.before.unknown_from})",
                        "logged_rules": list(item.logged_rules),
                        "sessions": item.sessions,
                    }
                )
        if sample < min_sample:
            status = "insufficient_sample"
        elif (agree / sample) < threshold:
            status = "below_threshold"
        else:
            status = "ok"
        results[zone_pair] = CalibrationResult(
            zone_pair=zone_pair,
            sample_sessions=sample,
            agreeing_sessions=agree,
            status=status,
            threshold=threshold,
            min_sample=min_sample,
            mismatch_examples=tuple(mismatches),
        )
    return results


def apply_calibration_gate(
    evaluated: list[EvaluatedTuple], calibration: dict[tuple[str, str], CalibrationResult]
) -> list[EvaluatedTuple]:
    """Downgrade every evaluated tuple in a zone-pair that failed calibration to
    INDETERMINATE, regardless of what the evaluator itself concluded. Fail
    closed: an untrusted zone-pair can report nothing but "unknown"."""
    from .evaluator import Classification

    downgraded = []
    for item in evaluated:
        result = calibration.get(_zone_pair(item))
        if result is not None and not result.trusted:
            downgraded.append(
                EvaluatedTuple(
                    flow=item.flow,
                    before=item.before,
                    after=item.after,
                    classification=Classification.INDETERMINATE,
                    direction=None,
                    sessions=item.sessions,
                    bytes_=item.bytes_,
                    first_seen=item.first_seen,
                    last_seen=item.last_seen,
                    logged_rules=item.logged_rules,
                )
            )
        else:
            downgraded.append(item)
    return downgraded
