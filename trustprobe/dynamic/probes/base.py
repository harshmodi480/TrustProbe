"""Probe base class and the context every probe receives.

A probe is one class with a `rule_id`, metadata, and `run(ctx) -> list[Finding]`. Drop a new
file in this package and it is discovered automatically (see `__init__.py`).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import ClassVar, Iterator

from trustprobe.config import ScanConfig
from trustprobe.dynamic.inputs import SHELL_KINDS, TestInput
from trustprobe.llm import LlmClient
from trustprobe.mcp_client import CallRecord
from trustprobe.models import Category, Confidence, Evidence, Finding, ServerSurface, Severity, ToolSnapshot
from trustprobe.sandbox.monitor import Attributed
from trustprobe.static.patterns import excerpt

ARG_VALUE_LIMIT = 200
OUTPUT_LIMIT = 1500


@dataclass
class ProbeContext:
    cfg: ScanConfig
    nonce: str
    surface: ServerSurface
    calls: list[CallRecord]  # every MCP call, in order (tools, prompts, resources)
    inputs: dict[int, TestInput]  # call index -> the planned input (tool calls only)
    events: list[Attributed]  # syscall events, attributed to calls, startup or idle
    snapshots: list[ToolSnapshot]
    list_changed_seen: bool = False
    capabilities: set[str] = field(default_factory=set)  # inferred by the static rules
    declared: set[str] = field(default_factory=set)  # declared by the operator
    watchdog_fired: bool = False
    llm: LlmClient | None = None  # optional second-opinion client; None when disabled

    def tool_calls(self) -> Iterator[tuple[int, CallRecord]]:
        for i, call in enumerate(self.calls):
            if call.kind == "tool":
                yield i, call

    def events_for(self, call_index: int) -> list[Attributed]:
        return [a for a in self.events if a.call is not None and a.call.index == call_index]


class Probe:
    """Subclass, set the class attributes, implement `run`."""

    rule_id: ClassVar[str]
    title: ClassVar[str]
    category: ClassVar[Category]
    severity: ClassVar[Severity]
    confidence: ClassVar[Confidence]
    description: ClassVar[str]
    impact: ClassVar[str]
    remediation: ClassVar[str]
    requires_monitor: ClassVar[bool] = False  # needs the syscall log (strace)
    requires_llm: ClassVar[bool] = False  # optional: runs only when an LLM client is configured, never counted as skipped

    def run(self, ctx: ProbeContext) -> list[Finding]:
        raise NotImplementedError

    def finding(
        self,
        target: str,
        evidence: list[Evidence],
        *,
        severity: Severity | None = None,
        confidence: Confidence | None = None,
        title: str | None = None,
        description: str | None = None,
    ) -> Finding:
        return Finding(
            id=f"{self.rule_id}:{target}",
            rule_id=self.rule_id,
            title=title or self.title,
            category=self.category,
            severity=severity or self.severity,
            confidence=confidence or self.confidence,
            target=target,
            phase="dynamic",
            description=description or self.description,
            impact=self.impact,
            remediation=self.remediation,
            evidence=evidence[:8],
        )


# --------------------------------------------------------------------------- evidence helpers


def trim_args(args: dict | None) -> dict | None:
    """Arguments for evidence: long strings are shortened so reports stay small."""
    if args is None:
        return None
    out = {}
    for k, v in args.items():
        if isinstance(v, str) and len(v) > ARG_VALUE_LIMIT:
            v = f"{v[:ARG_VALUE_LIMIT]}... ({len(v)} chars)"
        out[k] = v
    return out


def format_call(call: CallRecord) -> str:
    args = trim_args(call.arguments) or {}
    shown = ", ".join(f"{k}={v!r}" for k, v in args.items())
    return f"{call.name}({shown})"


def call_evidence(call: CallRecord, *, matched: str | None = None, summary: str | None = None, text: str | None = None) -> Evidence:
    """A tool_call evidence item: the call and an excerpt of what came back around `matched`."""
    body = call.scan_text if text is None else text
    if matched and matched in body:
        at = body.index(matched)
        detail = excerpt(body, at, at + len(matched), limit=OUTPUT_LIMIT)
    else:
        detail = excerpt(body, 0, 0, limit=OUTPUT_LIMIT) if body else (call.error or "")
    return Evidence(
        kind="tool_call",
        summary=summary or format_call(call),
        detail=detail[:2000],
        tool=call.name,
        arguments=trim_args(call.arguments),
        matched=matched,
    )


def syscall_evidence(att: Attributed, summary: str, matched: str | None = None) -> Evidence:
    return Evidence(kind="syscall", summary=summary, detail=att.event.raw[:2000], matched=matched)


def where(att: Attributed) -> str:
    """'during call to get_weather', 'during server startup', or 'while the server was idle'."""
    if att.call is not None:
        return f"during call to {att.call.name}"
    return "during server startup" if att.phase == "startup" else "while the server was idle"


def shell_proof(ctx: ProbeContext) -> dict[str, list[int]]:
    """Tools whose hostile shell inputs provably ran: tool name -> call indexes.

    Shared by DY-006 (which reports it) and DY-007 (which folds its process-spawn evidence in).
    """
    proof = f"TPROBE-{ctx.nonce}-42"
    found: dict[str, list[int]] = {}
    for i, call in ctx.tool_calls():
        ti = ctx.inputs.get(i)
        if ti and ti.hostile and ti.kind in SHELL_KINDS and proof in call.scan_text:
            found.setdefault(call.name, []).append(i)
    return found
