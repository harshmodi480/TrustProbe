"""DY-009 (optional, LLM): does what the sandbox saw during a tool's calls match its description?"""

import posixpath

from trustprobe.dynamic.probes.base import Probe, ProbeContext
from trustprobe.dynamic.probes.egress import _loopback
from trustprobe.dynamic.probes.filesystem import outside_allowed
from trustprobe.dynamic.probes.process_spawn import is_spawn
from trustprobe.llm import DY009, behavior_finding
from trustprobe.models import Category, Confidence, Finding, Severity
from trustprobe.sandbox.honeytokens import is_honeytoken_path

# Opens of these are the interpreter and the server's own code, not behavior worth showing a model.
RUNTIME_PREFIXES = ("/usr/", "/lib", "/etc/ld.so", "/etc/localtime", "/etc/nsswitch", "/etc/resolv", "/etc/hosts",
                    "/proc/", "/sys/", "/dev/", "/app/", "/tmp/", "/etc/ssl/", "/etc/passwd")
MAX_EVENTS = 20


def observed_lines(ctx: ProbeContext, tool: str) -> list[str]:
    """Short summaries of the notable syscalls that happened during this tool's calls."""
    lines: list[str] = []
    for att in ctx.events:
        if att.call is None or att.call.name != tool:
            continue
        ev = att.event
        if ev.syscall in ("open", "openat") and ev.path and not ev.is_write:
            if is_honeytoken_path(ev.path):
                lines.append(f"opened a credential file: {ev.path}")
            elif not ev.path.startswith(RUNTIME_PREFIXES):
                lines.append(f"opened {ev.path}")
        elif ev.is_write and any(p and outside_allowed(p) for p in (ev.path, ev.path2)):
            lines.append(f"{ev.syscall} {ev.path}")
        elif ev.syscall == "connect" and ev.family in ("AF_INET", "AF_INET6") and ev.addr and not _loopback(ev.addr):
            lines.append(f"network connection to {ev.addr}")
        elif ev.syscall == "execve" and is_spawn(ev.path):
            lines.append(f"started process {posixpath.basename(ev.path or '')}: {' '.join(ev.argv or [])[:120]}")
    return list(dict.fromkeys(lines))[:MAX_EVENTS]  # de-duplicated, in order


class BehaviorMismatch(Probe):
    rule_id = DY009["rule_id"]
    title = DY009["title"]
    category = Category.tool_poisoning
    severity = Severity.medium
    confidence = Confidence.llm_opinion
    description = DY009["description"]
    impact = DY009["impact"]
    remediation = DY009["remediation"]
    requires_monitor = True
    requires_llm = True

    def run(self, ctx: ProbeContext) -> list[Finding]:
        if ctx.llm is None:
            return []
        findings = []
        for tool in ctx.surface.tools:
            events = observed_lines(ctx, tool["name"])
            if not events:
                continue  # nothing notable was observed, so there is nothing to compare
            opinion = ctx.llm.compare_behavior(tool.get("description") or "", events)
            finding = behavior_finding(tool["name"], opinion, events) if opinion else None
            if finding:
                findings.append(finding)
        return findings
