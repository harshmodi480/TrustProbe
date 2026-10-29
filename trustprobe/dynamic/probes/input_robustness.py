"""DY-006: a hostile input was executed. DY-010: a hostile input crashed or hung the server, or an error leaked a stack trace."""

import posixpath
import re

from trustprobe.dynamic.inputs import SHELL_KINDS, TRAVERSAL_KINDS
from trustprobe.dynamic.probes.base import Probe, ProbeContext, call_evidence, shell_proof, syscall_evidence
from trustprobe.models import Category, Confidence, Evidence, Finding, Severity

PASSWD_PROOF = "root:x:0:0:"
SQL_SIGNATURES = re.compile(
    r"sqlite3\.OperationalError|SQLSTATE|syntax error at or near|You have an error in your SQL syntax|ORA-\d{5}|psycopg2\.errors\.|pymysql\.err\.",
    re.IGNORECASE,
)
STACK_TRACE = re.compile(r"Traceback \(most recent call last\)|^\s+at .+\(.+:\d+:\d+\)\s*$|File \".+\", line \d+", re.MULTILINE)


class InjectionExecuted(Probe):
    rule_id = "DY-006"
    title = "Hostile input was executed"
    category = Category.input_handling
    severity = Severity.critical
    confidence = Confidence.confirmed
    description = "A tool acted on a hostile input in a way that proves it was interpreted, not treated as plain data."
    impact = "Anything the model passes to this tool can run commands, read arbitrary files or alter queries."
    remediation = "Never build shell commands, file paths or queries from raw input. Use argument lists, allow-lists and parameterized queries."

    def run(self, ctx: ProbeContext) -> list[Finding]:
        proof = f"TPROBE-{ctx.nonce}-42"
        by_target: dict[str, list[tuple[str, Evidence]]] = {}  # tool -> [(kind, evidence)]
        for i, call in ctx.tool_calls():
            ti = ctx.inputs.get(i)
            if not ti or not ti.hostile:
                continue
            text = call.scan_text
            if ti.kind in SHELL_KINDS and proof in text:
                found = ("shell", call_evidence(call, matched=proof, summary=f"shell metacharacters executed: {call.name}"))
            elif ti.kind in TRAVERSAL_KINDS and PASSWD_PROOF in text:
                found = ("traversal", call_evidence(call, matched=PASSWD_PROOF, summary=f"path traversal read /etc/passwd: {call.name}"))
            elif (m := SQL_SIGNATURES.search(text)):
                found = ("sql", call_evidence(call, matched=m.group(0), summary=f"SQL error signature in the reply: {call.name}"))
            else:
                continue
            by_target.setdefault(call.name, []).append(found)

        spawned = shell_proof(ctx)
        findings = []
        for target, items in by_target.items():
            kinds = {k for k, _ in items}
            evidence = [e for _, e in items]
            if target in spawned:  # fold DY-007 into this finding
                for att in ctx.events:
                    if att.event.syscall == "execve" and att.call is not None and att.call.name == target and att.call.index in spawned[target]:
                        base = posixpath.basename(att.event.path or "")
                        evidence.append(syscall_evidence(att, f"also spawned {base} during the call (DY-007, merged)", att.event.path))
                        break
            hard = kinds & {"shell", "traversal"}
            titles = {"shell": "Shell command injection executed", "traversal": "Path traversal read a system file", "sql": "SQL error signature in the response"}
            findings.append(self.finding(
                target, evidence,
                severity=Severity.critical if hard else Severity.medium,
                confidence=Confidence.confirmed if hard else Confidence.pattern_match,
                title=titles[next(iter(kinds))] if len(kinds) == 1 else "Hostile input was executed",
            ))
        return findings


class CrashOrLeak(Probe):
    rule_id = "DY-010"
    title = "Server crashed, hung or leaked a stack trace on bad input"
    category = Category.input_handling
    severity = Severity.low
    confidence = Confidence.confirmed
    description = "A hostile input made the server exit or time out, or an error reply included a stack trace."
    impact = "Crashes are a denial-of-service risk, and stack traces reveal internal paths and code to anyone who can trigger an error."
    remediation = "Validate input, catch exceptions, and return short error messages without internals."

    def run(self, ctx: ProbeContext) -> list[Finding]:
        by_target: dict[str, list[Evidence]] = {}
        for i, call in ctx.tool_calls():
            ti = ctx.inputs.get(i)
            hostile = bool(ti and ti.hostile)
            if hostile and call.timed_out:
                by_target.setdefault(call.name, []).append(call_evidence(
                    call, matched="timeout", summary=f"hang on hostile input: {call.name}", text=f"timeout: {call.error}"))
            elif hostile and call.connection_lost and not ctx.watchdog_fired:
                by_target.setdefault(call.name, []).append(call_evidence(
                    call, matched="connection lost", summary=f"server exited on hostile input: {call.name}", text=f"connection lost: {call.error}"))
            elif call.is_error and (m := STACK_TRACE.search(call.text)):
                by_target.setdefault(call.name, []).append(call_evidence(call, matched=m.group(0), summary=f"stack trace in an error reply: {call.name}", text=call.text))
        return [self.finding(target, evidence) for target, evidence in by_target.items()]
