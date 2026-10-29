"""DY-005: a tool's output contains instructions aimed at the model."""

import re

from trustprobe.dynamic.probes.base import Probe, ProbeContext, call_evidence
from trustprobe.models import Category, Confidence, Evidence, Finding, Severity
from trustprobe.static.analyzer import rule_patterns

MIN_ECHO_LENGTH = 4


def strip_echo(text: str, arguments: dict | None) -> str:
    """Remove anything we sent from the output, so a server that merely echoes our input is not blamed for it."""
    for value in (arguments or {}).values():
        if isinstance(value, str) and len(value) >= MIN_ECHO_LENGTH:
            text = text.replace(value, " ")
    return text


class OutputInjection(Probe):
    rule_id = "DY-005"
    title = "Instructions to the model inside tool output"
    category = Category.output_injection
    severity = Severity.high
    confidence = Confidence.pattern_match
    description = "A tool result contains instructions meant for the AI model (hidden directives, concealment, or tool-call commands) that were not part of the input we sent."
    impact = "The tool's output is read by the model as if it were trusted, so the server can steer the agent after it has been approved."
    remediation = "Return data only. Never put directives in a tool result."

    def run(self, ctx: ProbeContext) -> list[Finding]:
        patterns: list[re.Pattern[str]] = rule_patterns(["TP-001", "TP-005", "PR-002"])
        by_target: dict[str, list[Evidence]] = {}
        for _, call in ctx.tool_calls():
            text = strip_echo(call.scan_text, call.arguments)
            for rx in patterns:
                m = rx.search(text)
                if m:
                    by_target.setdefault(call.name, []).append(call_evidence(call, matched=m.group(0), text=text))
                    break
        return [self.finding(target, evidence) for target, evidence in by_target.items()]
