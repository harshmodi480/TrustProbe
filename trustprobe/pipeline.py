"""Scan pipeline: sandbox -> MCP session -> static rules -> probes -> scored result -> files."""

from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from trustprobe import __version__
from trustprobe.config import ScanConfig
from trustprobe.dynamic.runner import (
    DynamicAnalysis,
    SessionData,
    adopt_client,
    analyze_session,
    rerun_static_on_snapshots,
    run_session,
)
from trustprobe.llm import LlmClient, explain_findings, review_surface
from trustprobe.mcp_client import ClientError, McpClient
from trustprobe.models import Finding, ScanResult, ServerSurface
from trustprobe.redact import Redactor
from trustprobe.sandbox.docker import Sandbox, SandboxError
from trustprobe.scoring import compute_verdict, trust_score
from trustprobe.static.analyzer import AnalysisResult, analyze

NOT_COVERED = [
    "Behavior after the observation window or on inputs other than those tried",
    "Servers that detect the sandbox and behave differently",
    "Vulnerabilities in third-party dependencies",
    "Remote (HTTP or SSE) transports",
]
INVENTORY_DESCRIPTION_LIMIT = 300


# --------------------------------------------------------------------------- files


def save_surface(surface: ServerSurface, path: Path, redactor: Redactor | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = surface.model_dump(mode="json")
    if redactor:
        data = redactor.obj(data)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def load_surface(path: Path) -> ServerSurface:
    if not path.is_file():
        raise SandboxError(f"surface file not found: {path}")
    try:
        return ServerSurface.model_validate(json.loads(path.read_text(encoding="utf-8")))
    except (ValueError, json.JSONDecodeError) as e:
        raise SandboxError(f"surface file {path.name} is not a valid saved surface: {e}") from e


def load_result(path: Path) -> dict:
    if not path.is_file():
        raise SandboxError(f"results file not found: {path}; run `trustprobe scan` first")
    return json.loads(path.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- running the server


async def _session(cfg: ScanConfig, sandbox: Sandbox, nonce: str, probe: bool, data: SessionData,
                   on_connected: Callable[[str, str | None], None] | None) -> None:
    command, args = sandbox.server_process()
    client = McpClient(
        command, args,
        startup_timeout_s=cfg.server.startup_timeout_s,
        call_timeout_s=cfg.scan.dynamic.call_timeout_s,
        stderr_log=sandbox.out_dir / "logs" / "server_stderr.log",
    )
    try:
        async with client:
            if on_connected:
                on_connected(client.server_name, client.server_version)
            await run_session(client, cfg, nonce, data, probe=probe)
    except ClientError:
        raise
    except Exception as e:  # noqa: BLE001 - keep what was recorded before the failure
        if client.session is None:
            raise ClientError(f"could not connect to the server: {e}") from e
        if not data.finished:
            data.notes.append(f"session ended early: {type(e).__name__}: {e}")
    finally:
        adopt_client(data, client)


def run_server(cfg: ScanConfig, sandbox: Sandbox, nonce: str, *, probe: bool,
               on_connected: Callable[[str, str | None], None] | None = None) -> SessionData:
    """Start the server in the (prepared) sandbox, enumerate it and, if `probe`, call everything."""
    data = SessionData(started=time.time())
    sandbox.start_watchdog()
    try:
        asyncio.run(_session(cfg, sandbox, nonce, probe, data, on_connected))
    except ClientError as e:
        if sandbox.timed_out:
            raise SandboxError(f"scan exceeded the {cfg.scan.total_timeout_s}s time limit; the container was killed") from e
        raise SandboxError(f"{e}. See logs/server_stderr.log in the output directory for the server's stderr.") from e
    data.ended = time.time()
    if sandbox.timed_out:
        data.notes.append(f"the {cfg.scan.total_timeout_s}s scan time limit was reached and the container was killed")
        data.finished = False
    sandbox.read_trace()  # copy the syscall log to out/audit/ before cleanup removes the volume
    return data


def enumerate_in_sandbox(cfg: ScanConfig, sandbox: Sandbox) -> ServerSurface:
    """Read everything the server advertises, without calling any tool."""
    data = run_server(cfg, sandbox, "00000000", probe=False)
    assert data.surface is not None
    return data.surface


# --------------------------------------------------------------------------- analysis and result


def make_llm(cfg: ScanConfig, redactor: Redactor) -> tuple[LlmClient | None, str | None]:
    """The optional LLM client, or (None, note). A missing key or package never stops a scan."""
    return LlmClient.from_config(cfg.llm, scrub=redactor.text)


def static_analysis(cfg: ScanConfig, surface: ServerSurface, llm: LlmClient | None = None) -> AnalysisResult:
    """The static rules, plus the optional LR-001 model review when `scan.static.llm_review` is on."""
    src = cfg.server.source
    result = analyze(
        surface,
        declared_capabilities=cfg.server.declared_capabilities,
        source={"type": src.type, "package": src.package, "version": src.version},
    )
    if llm is not None and cfg.scan.static.llm_review:
        result.findings += review_surface(llm, surface)
        result.rules_run.append("LR-001")
    return result


def attach_llm_info(result: ScanResult, cfg: ScanConfig, llm: LlmClient | None, note: str | None) -> None:
    """Add plain-language explanations and the coverage entry for the optional LLM checks."""
    explanations = explain_findings(llm, result.findings) if llm is not None else {}
    if explanations:
        result.meta["explanations"] = explanations
    result.coverage["llm"] = {
        "enabled": cfg.llm.enabled,
        "active": llm is not None,
        "model": llm.model if llm else None,
        "static_review": bool(llm and cfg.scan.static.llm_review),
        "behavior_check": bool(llm and result.coverage["mode"] == "full" and "DY-009" in result.coverage["dynamic_probes_run"]),
        "explained": len(explanations),
        "calls": llm.calls if llm else 0,
        "failures": llm.failures if llm else 0,
        "refusals": llm.refusals if llm else 0,
        "discarded_replies": llm.discarded if llm else 0,
        "note": note,
    }
    if note:
        result.coverage["notes"].append(note)


def _inventory(surface: ServerSurface) -> dict:
    def short(text: str | None) -> str:
        return (text or "")[:INVENTORY_DESCRIPTION_LIMIT]

    return {
        "tools": [{"name": t["name"], "description": short(t.get("description"))} for t in surface.tools],
        "prompts": [{"name": p["name"], "description": short(p.get("description"))} for p in surface.prompts],
        "resources": [{"name": r.get("name") or r["uri"], "uri": r["uri"], "description": short(r.get("description"))}
                      for r in surface.resources],
    }


def build_result(
    cfg: ScanConfig,
    nonce: str,
    surface: ServerSurface,
    static: AnalysisResult,
    *,
    mode: str,  # "full" | "static"
    data: SessionData | None = None,
    dyn: DynamicAnalysis | None = None,
    snapshot_findings: list[Finding] | None = None,
    monitor_note: str | None = None,
    timed_out: bool = False,
    started: float,
    server_run: bool = True,
) -> ScanResult:
    findings = [*static.findings, *(snapshot_findings or []), *(dyn.findings if dyn else [])]
    notes: list[str] = list(data.notes if data else [])
    incomplete: list[str] = []

    if mode == "full":
        if data is None or not data.finished:
            incomplete.append("the probing session did not finish")
        if dyn is not None:
            incomplete += [f"probe {k} skipped: {v}" for k, v in dyn.probes_skipped.items()]
            incomplete += [f"probe {k} failed: {v}" for k, v in dyn.probe_errors.items()]
            notes += dyn.notes
    if static.rule_errors:
        incomplete += [f"rule {k} failed: {v}" for k, v in static.rule_errors.items()]
    if timed_out:
        incomplete.append("scan time limit reached")

    verdict, reason = compute_verdict(
        findings,
        do_not_use_on=cfg.policy.do_not_use_on,
        static_only=(mode != "full"),
        dynamic_complete=not incomplete,
    )

    if mode == "full":
        dynamic_state = "ran" if not incomplete else "partial: " + "; ".join(incomplete)
    elif server_run:
        dynamic_state = "skipped: static-only mode"
    else:
        dynamic_state = "skipped: saved surface supplied (the server was not run)"

    calls = data.calls if data else []
    tool_calls = [c for c in calls if c.kind == "tool"]
    coverage = {
        "mode": mode,
        "dynamic": dynamic_state,
        "static_rules_run": sorted(static.rules_run),
        "static_rule_errors": static.rule_errors,
        "dynamic_probes_run": sorted(dyn.probes_run) if dyn else [],
        "dynamic_probes_skipped": dyn.probes_skipped if dyn else {},
        "dynamic_probe_errors": dyn.probe_errors if dyn else {},
        "tools_total": len(surface.tools),
        "tools_called": len({c.name for c in tool_calls}),
        "prompts_total": len(surface.prompts),
        "prompts_fetched": len({c.name for c in calls if c.kind == "prompt"}),
        "resources_total": len(surface.resources) + len(surface.resource_templates),
        "resources_read": len({c.name for c in calls if c.kind == "resource"}),
        "calls_made": len(tool_calls),
        "hostile_inputs_sent": data.hostile_inputs_sent if data else 0,
        "syscall_events": dyn.syscall_events if dyn else 0,
        "snapshots": [s.label for s in (data.snapshots if data else [])],
        "monitor_note": monitor_note,
        "capabilities_inferred": static.capabilities,
        "capabilities_observed": dyn.observed_capabilities if dyn else [],
        "notes": notes,
        "not_covered": NOT_COVERED,
    }
    caps = sorted(set(static.capabilities) | set(dyn.observed_capabilities if dyn else []))

    src = cfg.server.source
    meta = {
        "target": cfg.name,
        "server_name": surface.server_name,
        "server_version": surface.server_version,
        "source": f"{src.type}:{src.path or src.package}",
        "scanner_version": __version__,
        "mode": mode,
        "nonce": nonce,
        "started": datetime.fromtimestamp(started, timezone.utc).isoformat(timespec="seconds"),
        "duration_s": round(time.time() - started, 1),
        "tool_calls_made": len(tool_calls),
        "verdict_reason": reason,
        "inventory": _inventory(surface),
    }
    return ScanResult(meta=meta, coverage=coverage, findings=findings, trust_score=trust_score(findings),
                      verdict=verdict, capabilities=caps)


def full_analysis(cfg: ScanConfig, nonce: str, data: SessionData, sandbox: Sandbox,
                  llm: LlmClient | None = None) -> tuple[AnalysisResult, DynamicAnalysis, list[Finding]]:
    """Static rules, the probes and the snapshot re-run for a finished full session."""
    assert data.surface is not None
    static = static_analysis(cfg, data.surface, llm)
    dyn = analyze_session(
        cfg, nonce, data, sandbox.read_trace(),
        monitor_enabled=sandbox.monitor.enabled,
        capabilities=set(static.capabilities),
        watchdog_fired=sandbox.timed_out,
        llm=llm,
    )
    snapshot_findings = rerun_static_on_snapshots(data, cfg, {f.id for f in static.findings})
    return static, dyn, snapshot_findings


# --------------------------------------------------------------------------- output files


def write_outputs(result: ScanResult, surface: ServerSurface, out_dir: Path, redactor: Redactor) -> dict[str, Path]:
    """results.json, surface.json and report.html, with host details redacted. Returns the paths."""
    from trustprobe.report.render import render_report

    out_dir.mkdir(parents=True, exist_ok=True)
    data = redactor.obj(result.model_dump(mode="json"))
    results_path = out_dir / "results.json"
    results_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    save_surface(surface, out_dir / "surface.json", redactor)
    report_path = out_dir / "report.html"
    report_path.write_text(render_report(data), encoding="utf-8")
    return {"results": results_path, "surface": out_dir / "surface.json", "report": report_path}


def redact_logs(out_dir: Path, redactor: Redactor) -> None:
    """The server's stderr and the syscall log can quote host paths (for example Docker errors)."""
    for rel in ("logs/server_stderr.log", "audit/trace.log"):
        p = out_dir / rel
        if p.is_file():
            p.write_text(redactor.text(p.read_text(encoding="utf-8", errors="replace")), encoding="utf-8")
