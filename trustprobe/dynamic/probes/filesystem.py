"""DY-002: a planted secret file was opened. DY-008: a write attempt outside the allowed directories."""

import posixpath

from trustprobe.dynamic.probes.base import Probe, ProbeContext, syscall_evidence, where
from trustprobe.models import Category, Confidence, Evidence, Finding, Severity
from trustprobe.sandbox.honeytokens import is_honeytoken_path

# The server runs in /app, so a relative path is a path under /app.
WORKDIR = "/app"
# Directories a server may write to. /proc is kernel state, not storage (see DECISIONS.md).
ALLOWED_WRITE_DIRS = ("/tmp", "/workspace", "/audit", "/home/sandbox", "/dev", "/proc")


def resolve(path: str) -> str:
    return posixpath.normpath(path if path.startswith("/") else posixpath.join(WORKDIR, path))


def outside_allowed(path: str) -> bool:
    norm = resolve(path)
    return not any(norm == d or norm.startswith(d + "/") for d in ALLOWED_WRITE_DIRS)


class HoneytokenFileOpened(Probe):
    rule_id = "DY-002"
    title = "Honeytoken file opened"
    category = Category.data_exfiltration
    severity = Severity.high
    confidence = Confidence.confirmed
    description = "The server opened one of the planted fake secret files (~/.ssh, ~/.aws or ~/.env)."
    impact = "A real deployment would read the user's actual credentials."
    remediation = "Do not read credential files. Restrict file access to a declared directory."
    requires_monitor = True

    def run(self, ctx: ProbeContext) -> list[Finding]:
        by_target: dict[str, list[Evidence]] = {}
        for att in ctx.events:
            ev = att.event
            if ev.syscall in ("open", "openat") and is_honeytoken_path(ev.path):
                by_target.setdefault(att.target, []).append(
                    syscall_evidence(att, f"{ev.syscall} of honeytoken path {where(att)}", ev.path))
        # The operator expected file access, so the same observation matters less.
        severity = Severity.medium if "filesystem" in ctx.declared else Severity.high
        return [self.finding(target, evidence, severity=severity) for target, evidence in by_target.items()]


class WriteOutsideAllowedDirs(Probe):
    rule_id = "DY-008"
    title = "Write attempt outside the allowed directories"
    category = Category.permissions
    severity = Severity.medium
    confidence = Confidence.confirmed
    description = "The server tried to create, modify, delete or rename something outside /tmp, /workspace, /audit, /home/sandbox and /dev."
    impact = "A real deployment could change files elsewhere on the user's machine."
    remediation = "Keep writes inside a declared working directory."
    requires_monitor = True

    def run(self, ctx: ProbeContext) -> list[Finding]:
        by_target: dict[str, list[Evidence]] = {}
        for att in ctx.events:
            ev = att.event
            if not ev.is_write:
                continue
            paths = [p for p in (ev.path, ev.path2) if p]
            bad = next((p for p in paths if outside_allowed(p)), None)
            if bad:
                by_target.setdefault(att.target, []).append(
                    syscall_evidence(att, f"{ev.syscall} of {bad} {where(att)}", bad))
        return [self.finding(target, evidence) for target, evidence in by_target.items()]
