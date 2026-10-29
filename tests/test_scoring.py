from trustprobe.models import Category, Confidence, Finding, Severity
from trustprobe.scoring import (
    DO_NOT_USE,
    NO_ISSUES_FOUND,
    USE_WITH_CAUTION,
    compute_verdict,
    exit_code,
    finding_penalty,
    trust_score,
)


def mk(rule="TP-001", target="t", sev=Severity.high, conf=Confidence.pattern_match) -> Finding:
    return Finding(
        id=f"{rule}:{target}", rule_id=rule, title="x", category=Category.tool_poisoning,
        severity=sev, confidence=conf, target=target, phase="static",
        description="d", impact="i", remediation="r", evidence=[],
    )


def test_penalty_table():
    assert finding_penalty(mk(sev=Severity.critical, conf=Confidence.confirmed)) == 40
    assert finding_penalty(mk(sev=Severity.high, conf=Confidence.pattern_match)) == 20
    assert finding_penalty(mk(sev=Severity.medium, conf=Confidence.heuristic)) == 4
    assert finding_penalty(mk(sev=Severity.low, conf=Confidence.llm_opinion)) == 1
    assert finding_penalty(mk(sev=Severity.info, conf=Confidence.confirmed)) == 0


def test_score_starts_at_100_and_floors_at_0():
    assert trust_score([]) == 100
    many = [mk(rule=f"R-{i}", sev=Severity.critical, conf=Confidence.confirmed) for i in range(5)]
    assert trust_score(many) == 0


def test_same_rule_and_target_counts_once():
    assert trust_score([mk(), mk()]) == 80
    assert trust_score([mk(target="a"), mk(target="b")]) == 60


def test_confirmed_critical_is_do_not_use():
    v, reason = compute_verdict([mk(sev=Severity.critical, conf=Confidence.confirmed)])
    assert v == DO_NOT_USE and "critical" in reason


def test_policy_changes_blocking_severities():
    f = [mk(sev=Severity.high, conf=Confidence.confirmed)]
    assert compute_verdict(f)[0] == USE_WITH_CAUTION
    assert compute_verdict(f, do_not_use_on=[Severity.high, Severity.critical])[0] == DO_NOT_USE


def test_two_confirmed_high_is_do_not_use():
    f = [mk(rule="A", sev=Severity.high, conf=Confidence.confirmed), mk(rule="B", sev=Severity.high, conf=Confidence.confirmed)]
    assert compute_verdict(f)[0] == DO_NOT_USE


def test_score_below_40_is_do_not_use():
    f = [mk(rule=f"R{i}", sev=Severity.high, conf=Confidence.pattern_match) for i in range(3)]  # 60 points
    assert trust_score(f) == 40
    f.append(mk(rule="R9", sev=Severity.medium, conf=Confidence.confirmed))
    assert trust_score(f) == 30
    assert compute_verdict(f)[0] == DO_NOT_USE


def test_llm_opinion_never_triggers_do_not_use_alone():
    f = [mk(rule=f"L{i}", sev=Severity.medium, conf=Confidence.llm_opinion) for i in range(10)]
    assert compute_verdict(f)[0] == USE_WITH_CAUTION  # medium severity present, but not do_not_use


def test_medium_or_above_is_caution():
    assert compute_verdict([mk(sev=Severity.medium, conf=Confidence.heuristic)])[0] == USE_WITH_CAUTION


def test_score_below_85_is_caution():
    f = [mk(rule=f"R{i}", sev=Severity.low, conf=Confidence.confirmed) for i in range(6)]  # 18 points
    assert trust_score(f) == 82
    assert compute_verdict(f)[0] == USE_WITH_CAUTION


def test_clean_result():
    assert compute_verdict([])[0] == NO_ISSUES_FOUND
    assert compute_verdict([mk(sev=Severity.info, conf=Confidence.heuristic)])[0] == NO_ISSUES_FOUND


def test_static_only_never_returns_no_issues_found():
    v, reason = compute_verdict([], static_only=True)
    assert v == USE_WITH_CAUTION and "dynamic analysis not run" in reason


def test_incomplete_dynamic_never_returns_no_issues_found():
    assert compute_verdict([], dynamic_complete=False)[0] == USE_WITH_CAUTION


def test_exit_codes():
    assert exit_code(NO_ISSUES_FOUND) == 0
    assert exit_code(USE_WITH_CAUTION) == 0
    assert exit_code(USE_WITH_CAUTION, "caution") == 1
    assert exit_code(DO_NOT_USE) == 2
    assert exit_code(DO_NOT_USE, "caution") == 2
