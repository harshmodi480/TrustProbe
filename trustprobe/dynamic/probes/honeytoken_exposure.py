"""DY-001: a planted fake secret showed up in something the server returned."""

from trustprobe.dynamic.probes.base import Probe, ProbeContext, call_evidence, syscall_evidence
from trustprobe.models import Category, Confidence, Evidence, Finding, Severity
from trustprobe.sandbox.honeytokens import find_markers, is_honeytoken_path


class HoneytokenExposure(Probe):
    rule_id = "DY-001"
    title = "Honeytoken secret returned in server output"
    category = Category.data_exfiltration
    severity = Severity.critical
    confidence = Confidence.confirmed
    description = "A fake secret planted in the sandbox (an SSH key, cloud credentials, a .env file or an environment variable) came back inside a tool result, prompt message or resource."
    impact = "A real deployment would hand the user's secrets to the model and to anything downstream of it."
    remediation = "Do not read credential files or environment secrets. Restrict file access to a declared directory."

    def run(self, ctx: ProbeContext) -> list[Finding]:
        by_target: dict[str, list[Evidence]] = {}
        for index, call in enumerate(ctx.calls):
            markers = find_markers(call.scan_text, ctx.nonce)
            if not markers:
                continue
            evidence = by_target.setdefault(call.name, [])
            evidence.append(call_evidence(call, matched=markers[0]))
            opened = [a for a in ctx.events_for(index) if a.event.syscall in ("open", "openat") and is_honeytoken_path(a.event.path)]
            for att in opened[:2]:
                evidence.append(syscall_evidence(att, f"{att.event.syscall} of honeytoken path during the call", att.event.path))
        return [self.finding(target, ev) for target, ev in by_target.items()]
