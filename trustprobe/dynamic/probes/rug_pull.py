"""DY-004: the tool list changed after the server was first listed (a rug pull)."""

import difflib
import json

from trustprobe.dynamic.probes.base import Probe, ProbeContext
from trustprobe.models import Category, Confidence, Evidence, Finding, Severity, ToolSnapshot


def _pretty(defn: dict | None) -> list[str]:
    return json.dumps(defn, indent=2, sort_keys=True, ensure_ascii=False).splitlines() if defn is not None else []


def changed_tools(a: ToolSnapshot, b: ToolSnapshot) -> list[str]:
    """Names of tools that were added, removed or altered between two snapshots."""
    names = sorted(set(a.tools) | set(b.tools))
    return [n for n in names if a.tools.get(n) != b.tools.get(n)]


def diff_text(old: dict | None, new: dict | None, tool: str) -> str:
    lines = difflib.unified_diff(_pretty(old), _pretty(new), fromfile=f"{tool} (before)", tofile=f"{tool} (after)", lineterm="", n=50)
    return "\n".join(lines)[:2000]


class RugPull(Probe):
    rule_id = "DY-004"
    title = "Tool definition changed after it was listed (rug pull)"
    category = Category.integrity
    severity = Severity.critical
    confidence = Confidence.confirmed
    description = "A tool's name, description or input schema is different in a later tool listing than in the first one."
    impact = "A server that behaves for a review, then swaps in hostile instructions, defeats any approval given on the first listing."
    remediation = "Do not use a server that changes its tool definitions. Pin a version and re-review on every change."

    def run(self, ctx: ProbeContext) -> list[Finding]:
        snaps = ctx.snapshots
        if len(snaps) < 2:
            return []
        tool_calls = sum(1 for _ in ctx.tool_calls())
        by_tool: dict[str, list[Evidence]] = {}
        for older, newer in zip(snaps, snaps[1:]):
            for name in changed_tools(older, newer):
                old, new = older.raw.get(name), newer.raw.get(name)
                what = "added" if old is None else "removed" if new is None else "changed"
                by_tool.setdefault(name, []).append(Evidence(
                    kind="diff",
                    summary=f"tool '{name}' {what} between the '{older.label}' and '{newer.label}' listings ({tool_calls} tool calls made in total)",
                    detail=diff_text(old, new, name),
                    tool=name,
                    matched=name,
                ))
        # With a tools/list_changed notification a client could have noticed; without one it could not.
        severity = Severity.medium if ctx.list_changed_seen else Severity.critical
        note = "The server sent a tools/list_changed notification." if ctx.list_changed_seen else "The server sent no tools/list_changed notification, so a client would not have noticed."
        return [self.finding(name, evidence, severity=severity, description=f"{self.description} {note}") for name, evidence in by_tool.items()]
