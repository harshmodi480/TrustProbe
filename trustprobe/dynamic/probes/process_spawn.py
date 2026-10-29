"""DY-007: the server started a shell, downloader or interpreter while handling a call."""

import posixpath

from trustprobe.dynamic.probes.base import Probe, ProbeContext, shell_proof, syscall_evidence
from trustprobe.models import Category, Confidence, Evidence, Finding, Severity

SPAWNED = {"sh", "bash", "dash", "curl", "wget", "nc", "ncat", "node"}


def is_spawn(path: str | None) -> bool:
    base = posixpath.basename(path or "")
    return base in SPAWNED or base.startswith("python")


class ProcessSpawned(Probe):
    rule_id = "DY-007"
    title = "Process spawned during a call"
    category = Category.permissions
    severity = Severity.high
    confidence = Confidence.confirmed
    description = "While handling a call the server started a shell, a download tool or an interpreter (execve)."
    impact = "A real deployment could run arbitrary commands on the user's machine."
    remediation = "Avoid spawning processes. If a tool needs one, pass an argument list instead of a shell string and validate every input."
    requires_monitor = True

    def run(self, ctx: ProbeContext) -> list[Finding]:
        # A tool whose shell injection was proven is reported by DY-006, with these events folded in.
        merged = set(shell_proof(ctx))
        by_target: dict[str, list[Evidence]] = {}
        for att in ctx.events:
            ev = att.event
            if att.phase != "call" or ev.syscall != "execve" or not is_spawn(ev.path) or att.target in merged:
                continue
            argv = " ".join(ev.argv or [])[:200]
            by_target.setdefault(att.target, []).append(
                syscall_evidence(att, f"execve of {ev.path} during call to {att.target}: {argv}", ev.path))
        # Spawning is expected from a server that is known to use a shell.
        expected = "shell" in ctx.declared or "shell" in ctx.capabilities
        severity = Severity.info if expected else Severity.high
        return [self.finding(target, evidence, severity=severity) for target, evidence in by_target.items()]
