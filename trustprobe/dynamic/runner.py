"""Dynamic runner: drive the probing session, then run the probes over what was observed.

`run_session` talks to the server (it needs a live MCP client). `analyze_session` is pure: it
takes the recorded session plus the syscall log and returns findings, so it can be tested
without Docker.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

import anyio

from trustprobe.config import ScanConfig
from trustprobe.dynamic.inputs import TestInput, expand_template, plan_for_tool
from trustprobe.dynamic.probes import ProbeContext, discover_probes
from trustprobe.dynamic.probes.base import Probe
from trustprobe.llm import LlmClient
from trustprobe.mcp_client import CallRecord, McpClient, make_snapshot
from trustprobe.models import Finding, ServerSurface, ToolSnapshot
from trustprobe.sandbox.monitor import Attributed, CallWindow, attribute, clock_is_plausible, parse_trace
from trustprobe.static.analyzer import analyze


@dataclass
class SessionData:
    """Everything recorded while the server was running."""

    started: float = 0.0
    ended: float = 0.0
    surface: ServerSurface | None = None
    snapshots: list[ToolSnapshot] = field(default_factory=list)
    calls: list[CallRecord] = field(default_factory=list)
    inputs: dict[int, TestInput] = field(default_factory=dict)  # call index -> planned input
    list_changed_seen: bool = False
    first_response_at: float | None = None
    probed: bool = False  # tool calls were made
    finished: bool = False  # the whole plan ran to the end
    notes: list[str] = field(default_factory=list)

    @property
    def tool_calls(self) -> list[CallRecord]:
        return [c for c in self.calls if c.kind == "tool"]

    @property
    def hostile_inputs_sent(self) -> int:
        return sum(1 for i, ti in self.inputs.items() if ti.hostile and i < len(self.calls))


@dataclass
class DynamicAnalysis:
    findings: list[Finding] = field(default_factory=list)
    probes_run: list[str] = field(default_factory=list)
    probes_skipped: dict[str, str] = field(default_factory=dict)
    probe_errors: dict[str, str] = field(default_factory=dict)
    observed_capabilities: list[str] = field(default_factory=list)
    syscall_events: int = 0
    notes: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- session


async def run_session(client: McpClient, cfg: ScanConfig, nonce: str, data: SessionData, *, probe: bool) -> None:
    """Enumerate the server and, if `probe`, call everything. Fills `data` as it goes."""
    surface = await client.enumerate_surface()
    data.surface = surface
    data.snapshots.append(make_snapshot("initial", surface.tools))
    data.first_response_at = client.first_response_at
    if not probe:
        data.finished = True
        return

    dyn = cfg.scan.dynamic
    data.probed = True
    lost = False
    sent = 0
    for tool in surface.tools:
        if lost or sent >= dyn.max_total_calls:
            break
        for ti in plan_for_tool(tool, nonce, max_calls=dyn.max_calls_per_tool):
            if sent >= dyn.max_total_calls:
                data.notes.append(f"max_total_calls ({dyn.max_total_calls}) reached; some planned calls were not made")
                break
            rec = await client.call_tool(tool["name"], ti.arguments)
            data.inputs[len(client.calls) - 1] = ti
            sent += 1
            if rec.connection_lost:
                lost = True
                data.notes.append(f"connection to the server was lost during a call to '{tool['name']}'; probing stopped")
                break

    if not lost:
        for p in surface.prompts:
            await client.get_prompt(p["name"], {a["name"]: "test" for a in (p.get("arguments") or [])})
        for r in surface.resources:
            await client.read_resource(r["uri"])
        for t in surface.resource_templates:
            await client.read_resource(expand_template(t["uriTemplate"]))

        data.snapshots.append(await client.snapshot("after_probes"))
        await anyio.sleep(dyn.rugpull_delay_s)
        data.snapshots.append(await client.snapshot("after_delay"))
        data.finished = True


def adopt_client(data: SessionData, client: McpClient) -> None:
    """Copy what the client recorded into the session data (also after a failure)."""
    data.calls = list(client.calls)
    data.list_changed_seen = client.list_changed_seen
    data.first_response_at = client.first_response_at


# --------------------------------------------------------------------------- analysis


def rerun_static_on_snapshots(data: SessionData, cfg: ScanConfig, known_ids: set[str]) -> list[Finding]:
    """Run the static rules on every later tool listing; keep findings not already reported."""
    if data.surface is None:
        return []
    out: list[Finding] = []
    seen = set(known_ids)
    for snap in data.snapshots[1:]:
        surface = data.surface.model_copy(update={"tools": list(snap.raw.values())})
        result = analyze(surface, declared_capabilities=cfg.server.declared_capabilities, label=snap.label, tools_only=True)
        for f in result.findings:
            if f.id not in seen:
                seen.add(f.id)
                out.append(f)
    return out


def _observed_capabilities(findings: list[Finding]) -> list[str]:
    caps = set()
    for f in findings:
        if f.rule_id == "DY-003":
            caps.add("network")
        elif f.rule_id == "DY-007" or (f.rule_id == "DY-006" and any("shell" in e.summary or "spawned" in e.summary for e in f.evidence)):
            caps.add("shell")
        elif f.rule_id in ("DY-001", "DY-002"):
            caps.update({"secrets", "filesystem"} if f.rule_id == "DY-002" else {"secrets"})
        elif f.rule_id == "DY-008":
            caps.add("filesystem")
    return sorted(caps)


def analyze_session(
    cfg: ScanConfig,
    nonce: str,
    data: SessionData,
    trace_text: str,
    *,
    monitor_enabled: bool,
    capabilities: set[str],
    watchdog_fired: bool = False,
    probes: list[Probe] | None = None,
    llm: LlmClient | None = None,
) -> DynamicAnalysis:
    """Parse the syscall log, attribute events to calls, and run every probe."""
    assert data.surface is not None
    out = DynamicAnalysis()

    events = parse_trace(trace_text) if monitor_enabled else []
    out.syscall_events = len(events)
    windows = [CallWindow(i, c.name, c.kind, c.start, c.end) for i, c in enumerate(data.calls)]
    attributed: list[Attributed] = attribute(events, windows, data.first_response_at)
    if events and not clock_is_plausible(events, data.started, data.ended or time.time()):
        out.notes.append("container and host clocks disagree by more than 2s; syscall events cannot be tied to individual calls reliably")
        attributed = [Attributed(a.event, "idle") for a in attributed]

    ctx = ProbeContext(
        cfg=cfg, nonce=nonce, surface=data.surface, calls=data.calls, inputs=data.inputs, events=attributed,
        snapshots=data.snapshots, list_changed_seen=data.list_changed_seen, capabilities=capabilities,
        declared=set(cfg.server.declared_capabilities), watchdog_fired=watchdog_fired, llm=llm,
    )
    for probe in (probes if probes is not None else discover_probes()):
        if probe.requires_llm and (llm is None or (probe.requires_monitor and not monitor_enabled)):
            continue  # optional check: not run, and not counted as a gap in the scan
        if probe.requires_monitor and not monitor_enabled:
            out.probes_skipped[probe.rule_id] = "strace unavailable in sandbox"
            continue
        try:
            out.findings += probe.run(ctx)
            out.probes_run.append(probe.rule_id)
        except Exception as e:  # noqa: BLE001 - a failing probe must not abort the scan
            out.probe_errors[probe.rule_id] = f"{type(e).__name__}: {e}"
    out.observed_capabilities = _observed_capabilities(out.findings)
    return out
