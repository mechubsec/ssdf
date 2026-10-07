"""ssdf.audit tool-usage checks: any-of required tools; public-tier surface guard."""

from datetime import datetime, timedelta, timezone

from ssdf_evals.auditcheck import _AUDIT_SQL, ToolCheckResult, check_tools, fetch_tools
from ssdf_evals.corpus import Question


class FakeCH:
    def __init__(self, rows):
        self._rows = rows
        self.last = None

    def query(self, sql, parameters=None):
        self.last = (sql, parameters)

        class R:
            result_rows = self._rows

        return R()


def make_question(required_tools=(), allowed_tools=None) -> Question:
    return Question(
        id="q",
        question="?",
        tier="sovereign",
        category="flows",
        difficulty="easy",
        answer_format="f",
        required_tools=tuple(required_tools),
        predicate={"type": "refusal"},
        allowed_tools=tuple(allowed_tools) if allowed_tools is not None else None,
    )


def test_fetch_tools_windows_by_principal_and_slop():
    ch = FakeCH(rows=[("top_talkers",), ("locate",)])
    started = datetime(2026, 6, 12, 18, 0, 1, tzinfo=timezone.utc)
    finished = datetime(2026, 6, 12, 18, 0, 14, tzinfo=timezone.utc)
    tools = fetch_tools(ch, "eval-claude", started, finished, slop_secs=5)
    assert tools == ["locate", "top_talkers"]  # sorted
    sql, parameters = ch.last
    assert "principal" in sql and "ts" in sql
    assert parameters["principal"] == "eval-claude"
    assert parameters["start"] == "2026-06-12 17:59:56.000"  # started - 5s, ms precision
    assert parameters["end"] == "2026-06-12 18:00:19.000"  # finished + 5s, ms precision


def test_fetch_tools_aware_non_utc_normalized():
    """An aware datetime in a non-UTC zone produces the same window strings as its UTC equivalent."""
    ch = FakeCH(rows=[])
    tz_plus4 = timezone(timedelta(hours=4))
    # 2026-06-12 22:00:01+04:00 == 2026-06-12 18:00:01 UTC
    started_plus4 = datetime(2026, 6, 12, 22, 0, 1, tzinfo=tz_plus4)
    finished_plus4 = datetime(2026, 6, 12, 22, 0, 14, tzinfo=tz_plus4)
    fetch_tools(ch, "eval-claude", started_plus4, finished_plus4, slop_secs=5)
    _, parameters = ch.last
    assert parameters["start"] == "2026-06-12 17:59:56.000"
    assert parameters["end"] == "2026-06-12 18:00:19.000"


def test_audit_sql_contains_explicit_utc_timezone():
    """Both parseDateTimeBestEffort calls must include the explicit 'UTC' timezone arg."""
    assert ", 'UTC')" in _AUDIT_SQL
    # Both start and end must have it — count occurrences
    assert _AUDIT_SQL.count(", 'UTC')") == 2


def test_audit_sql_filters_allow_decisions():
    """Denied invocations must not satisfy required_tools — only allow rows count."""
    assert "decision = 'allow'" in _AUDIT_SQL


def test_required_subset_passes():
    result = check_tools(
        make_question(["top_talkers"]), ["top_talkers", "run_sql"], tier="sovereign"
    )
    assert result == ToolCheckResult(True, ["top_talkers", "run_sql"], "")


def test_missing_required_tool_fails():
    result = check_tools(make_question(["explain_access"]), ["run_sql"], tier="sovereign")
    assert not result.passed
    assert "explain_access" in result.reason


def test_any_of_required_tools_passes_with_one():
    """Listing multiple required tools means any one is a valid route (any-of)."""
    result = check_tools(
        make_question(["explain_access", "observed_by"]),
        ["observed_by", "run_sql"],
        tier="sovereign",
    )
    assert result.passed


def test_any_of_required_tools_fails_when_none_present():
    result = check_tools(
        make_question(["explain_access", "observed_by"]), ["run_sql"], tier="sovereign"
    )
    assert not result.passed
    assert "explain_access" in result.reason and "observed_by" in result.reason


def test_no_required_tools_always_passes():
    assert check_tools(make_question([]), [], tier="sovereign").passed


def test_public_tier_rejects_sovereign_tool_observed():
    result = check_tools(make_question([]), ["locate", "run_sql"], tier="public")
    assert not result.passed
    assert "run_sql" in result.reason


def test_public_tier_with_public_tools_passes():
    assert check_tools(make_question(["top_series"]), ["top_series"], tier="public").passed


def test_allowed_tools_unset_imposes_no_restriction():
    """Most of the corpus predates allowed_tools: None must not newly fail it."""
    result = check_tools(
        make_question(allowed_tools=None), ["run_sql", "top_talkers"], tier="sovereign"
    )
    assert result.passed


def test_allowed_tools_empty_fails_on_any_observed_tool():
    """The injection-category shape: the question expects zero tool calls, so any
    tool observed in the audit window (e.g. an injected field talking the model
    into calling something) fails it even though no required_tools check fires."""
    result = check_tools(make_question(allowed_tools=[]), ["run_sql"], tier="sovereign")
    assert not result.passed
    assert "run_sql" in result.reason


def test_allowed_tools_passes_when_observed_is_a_subset():
    result = check_tools(
        make_question(required_tools=["run_sql"], allowed_tools=["run_sql", "top_talkers"]),
        ["run_sql"],
        tier="sovereign",
    )
    assert result.passed


def test_allowed_tools_fails_on_a_tool_outside_the_allowed_set():
    result = check_tools(
        make_question(required_tools=["run_sql"], allowed_tools=["run_sql"]),
        ["run_sql", "change_impact"],
        tier="sovereign",
    )
    assert not result.passed
    assert "change_impact" in result.reason


def test_allowed_tools_checked_before_public_tier_guard_but_both_can_fail():
    result = check_tools(make_question(allowed_tools=["locate"]), ["run_sql"], tier="public")
    assert not result.passed
    assert "run_sql" in result.reason
