"""Trust score and verdict. Pure functions: no I/O, no Docker, easy to unit test."""

from __future__ import annotations

from collections.abc import Iterable

from trustprobe.models import Confidence, Finding, Severity

SEVERITY_PENALTY = {
    Severity.critical: 40,
    Severity.high: 25,
    Severity.medium: 10,
    Severity.low: 3,
    Severity.info: 0,
}

CONFIDENCE_MULTIPLIER = {
    Confidence.confirmed: 1.0,
    Confidence.pattern_match: 0.8,
    Confidence.heuristic: 0.4,
    Confidence.llm_opinion: 0.3,
}

SEVERITY_ORDER = [Severity.info, Severity.low, Severity.medium, Severity.high, Severity.critical]
CONFIDENCE_ORDER = [Confidence.llm_opinion, Confidence.heuristic, Confidence.pattern_match, Confidence.confirmed]

DO_NOT_USE = "do_not_use"
USE_WITH_CAUTION = "use_with_caution"
NO_ISSUES_FOUND = "no_issues_found"

VERDICT_LABELS = {
    DO_NOT_USE: "Do not use",
    USE_WITH_CAUTION: "Use with caution",
    NO_ISSUES_FOUND: "No issues found in tested scenarios",
}


def severity_rank(s: Severity) -> int:
    return SEVERITY_ORDER.index(s)


def confidence_rank(c: Confidence) -> int:
    return CONFIDENCE_ORDER.index(c)


def finding_penalty(f: Finding) -> int:
    """Base penalty by severity times the confidence factor, rounded to the nearest integer."""
    return round(SEVERITY_PENALTY[f.severity] * CONFIDENCE_MULTIPLIER[f.confidence])


def distinct_findings(findings: Iterable[Finding]) -> list[Finding]:
    """One finding per (rule_id, target); the highest-penalty one wins."""
    best: dict[tuple[str, str], Finding] = {}
    for f in findings:
        key = (f.rule_id, f.target)
        if key not in best or finding_penalty(f) > finding_penalty(best[key]):
            best[key] = f
    return list(best.values())


def trust_score(findings: Iterable[Finding]) -> int:
    """Start at 100, subtract a penalty per distinct finding, never below 0."""
    total = sum(finding_penalty(f) for f in distinct_findings(findings))
    return max(0, 100 - total)


def compute_verdict(
    findings: Iterable[Finding],
    *,
    do_not_use_on: Iterable[Severity] = (Severity.critical,),
    static_only: bool = False,
    dynamic_complete: bool = True,
) -> tuple[str, str]:
    """Return (verdict, reason). Rules are evaluated in order; the first match wins.

    `dynamic_complete` is False when dynamic analysis was requested but did not fully
    run (Docker or strace missing, a probe errored).
    """
    items = distinct_findings(findings)
    score = trust_score(items)
    blocking = set(do_not_use_on)

    confirmed = [f for f in items if f.confidence == Confidence.confirmed]
    confirmed_blocking = [f for f in confirmed if f.severity in blocking]
    confirmed_high = [f for f in confirmed if f.severity == Severity.high]

    if confirmed_blocking:
        sev = max((f.severity for f in confirmed_blocking), key=severity_rank).value
        return DO_NOT_USE, f"Do not use: {len(confirmed_blocking)} confirmed {sev} finding(s)"
    if len(confirmed_high) >= 2:
        return DO_NOT_USE, f"Do not use: {len(confirmed_high)} confirmed high findings"
    if score < 40:
        return DO_NOT_USE, f"Do not use: trust score {score} is below 40"

    medium_up = [f for f in items if severity_rank(f.severity) >= severity_rank(Severity.medium)]
    if medium_up:
        return USE_WITH_CAUTION, f"Use with caution: {len(medium_up)} finding(s) at medium severity or above"
    if score < 85:
        return USE_WITH_CAUTION, f"Use with caution: trust score {score} is below 85"
    if static_only:
        return USE_WITH_CAUTION, "Use with caution: dynamic analysis not run"
    if not dynamic_complete:
        return USE_WITH_CAUTION, "Use with caution: dynamic analysis requested but not fully run"

    return NO_ISSUES_FOUND, "No issues found in tested scenarios (this is not a claim that the server is safe)"


def exit_code(verdict: str, fail_on: str = "do_not_use") -> int:
    """CI exit code. Do not use is always 2; Use with caution is 1 only with --fail-on caution."""
    if verdict == DO_NOT_USE:
        return 2
    if verdict == USE_WITH_CAUTION and fail_on == "caution":
        return 1
    return 0
