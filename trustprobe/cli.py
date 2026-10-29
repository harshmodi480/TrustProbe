"""TrustProbe command line interface."""

from __future__ import annotations

import shlex
import time
import webbrowser
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from trustprobe import __version__
from trustprobe.config import ConfigError, ScanConfig, load_config, new_nonce, parse_config, save_run_state
from trustprobe.llm import LR001
from trustprobe.models import Category, Confidence, Finding, ScanResult, ServerSurface
from trustprobe.pipeline import (
    attach_llm_info,
    build_result,
    full_analysis,
    load_result,
    load_surface,
    make_llm,
    redact_logs,
    run_server,
    static_analysis,
    write_outputs,
)
from trustprobe.quick import QuickError, build_quick_config
from trustprobe.redact import Redactor
from trustprobe.report.render import render_file
from trustprobe.sandbox.docker import Sandbox, SandboxError, docker_available
from trustprobe.scoring import VERDICT_LABELS, confidence_rank, exit_code, severity_rank
from trustprobe.static.analyzer import RuleError, load_rules

app = typer.Typer(help="Probe an MCP server in a sandbox and report what it does.", no_args_is_help=True)
rules_app = typer.Typer(help="List static rules and dynamic probes.")
app.add_typer(rules_app, name="rules")

console = Console()
err_console = Console(stderr=True)

EXIT_ERROR = 3
STEP_WIDTH = 46
ALWAYS_SHOWN = (Category.tool_poisoning, Category.data_exfiltration, Category.permissions, Category.network)


@app.callback()
def _main(version: bool = typer.Option(False, "--version", help="Show the version and exit.", is_eager=True)) -> None:
    if version:
        console.print(f"trustprobe {__version__}")
        raise typer.Exit()


def _fail(message: str, code: int = EXIT_ERROR) -> typer.Exit:
    err_console.print(f"[red]error:[/red] {message}")
    return typer.Exit(code)


def _load(config: Path) -> ScanConfig:
    try:
        return load_config(config)
    except ConfigError as e:
        err_console.print(f"[red]config error:[/red] {e}")
        raise typer.Exit(EXIT_ERROR)


# --------------------------------------------------------------------------- validate


@app.command()
def validate(config: Path = typer.Option(..., "-c", "--config", help="Path to scan.yaml")) -> None:
    """Validate the config and check Docker, without running the server."""
    cfg = _load(config)
    console.print(f"[green]config ok[/green]: {cfg.name} (runtime={cfg.runtime}, mode={cfg.scan.mode})")

    ok, info = docker_available()
    if ok:
        console.print(f"[green]docker ok[/green]: server {info}")
        return
    if cfg.scan.mode == "full" and cfg.scan.dynamic.enabled:
        err_console.print(f"[red]docker unavailable:[/red] {info}")
        raise typer.Exit(EXIT_ERROR)
    console.print(f"[yellow]docker unavailable:[/yellow] {info} (not needed for this config)")


# --------------------------------------------------------------------------- rules list


@rules_app.command("list")
def rules_list() -> None:
    """List static rules and dynamic probes with ids, categories and severities."""
    from trustprobe.dynamic.probes import discover_probes

    try:
        rules = load_rules()
    except RuleError as e:
        raise _fail(f"rule error: {e}")
    table = Table(show_header=True, header_style="bold")
    for col in ("ID", "Phase", "Category", "Severity", "Confidence", "Title"):
        table.add_column(col, no_wrap=col != "Title")
    for r in rules:
        table.add_row(r.id, "static", r.category.value, r.severity.value, r.confidence.value, r.title)
    table.add_row(LR001["rule_id"], "static (LLM)", LR001["category"].value, "medium max", "llm_opinion", LR001["title"])
    probes = discover_probes()
    for p in probes:
        phase = "dynamic (LLM)" if p.requires_llm else "dynamic"
        table.add_row(p.rule_id, phase, p.category.value, p.severity.value + (" max" if p.requires_llm else ""), p.confidence.value, p.title)
    console.print(table)
    console.print(f"{len(rules) + 1} static rules and {len(probes)} dynamic probes. The (LLM) ones need llm.enabled and an API key.")


# --------------------------------------------------------------------------- output helpers


def _step(n: int, label: str, outcome: str) -> None:
    dots = "." * max(3, STEP_WIDTH - len(label))
    console.print(f"[{n}/6] {label} {dots} {outcome}", markup=False)


def _category_rows(findings: list[Finding]) -> list[tuple[str, int, str]]:
    cats = list(ALWAYS_SHOWN) + sorted({f.category for f in findings if f.category not in ALWAYS_SHOWN}, key=lambda c: c.value)
    rows = []
    for cat in cats:
        mine = [f for f in findings if f.category == cat]
        if not mine:
            rows.append((cat.value, 0, "-"))
            continue
        worst = max(severity_rank(f.severity) for f in mine)
        top = [f for f in mine if severity_rank(f.severity) == worst]
        label = top[0].severity.value + (" (confirmed)" if any(f.confidence == Confidence.confirmed for f in top) else "")
        rows.append((cat.value, len(mine), label))
    return rows


def _print_top_findings(findings: list[Finding], limit: int = 10) -> None:
    ordered = sorted(findings, key=lambda f: (-severity_rank(f.severity), -confidence_rank(f.confidence), f.id))
    for f in ordered[:limit]:
        console.print(f"  {f.severity.value:<8} {f.confidence.value:<13} {f.id}", markup=False)
    if len(ordered) > limit:
        console.print(f"  ... and {len(ordered) - limit} more (see the report)", markup=False)


def _print_summary(result: ScanResult, report_path: Path) -> None:
    console.print()
    table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
    for col in ("Category", "Findings", "Worst"):
        table.add_column(col)
    for name, n, worst in _category_rows(result.findings):
        table.add_row(name, str(n), worst)
    console.print(table)
    if result.findings:
        console.print()
        _print_top_findings(result.findings)
    console.print()
    color = {"do_not_use": "red", "use_with_caution": "yellow", "no_issues_found": "green"}[result.verdict]
    console.print(f"  VERDICT: [bold {color}]{VERDICT_LABELS[result.verdict].upper()}[/bold {color}]   (trust score {result.trust_score}/100)")
    console.print(f"  {result.meta['verdict_reason']}")
    if result.coverage["mode"] != "full":
        console.print(f"  Note: dynamic analysis not run ({result.coverage['dynamic']}).", markup=False)
    for note in result.coverage["notes"]:
        console.print(f"  Note: {note}", markup=False)
    console.print(f"  Report: {report_path}", markup=False)
    console.print("  This is a result for the tested scenarios only, not a claim that the server is safe.")


def _finish(result: ScanResult, surface: ServerSurface, out_dir: Path, redactor: Redactor, fail_on: str) -> None:
    paths = write_outputs(result, surface, out_dir, redactor)
    redact_logs(out_dir, redactor)
    try:
        shown = paths["report"].relative_to(Path.cwd())
    except ValueError:
        shown = paths["report"]
    _print_summary(result, shown)
    raise typer.Exit(exit_code(result.verdict, fail_on))


# --------------------------------------------------------------------------- scan


@app.command()
def scan(
    config: Path = typer.Option(..., "-c", "--config", help="Path to scan.yaml"),
    static_only: bool = typer.Option(False, "--static-only", help="Enumerate in the sandbox but make no tool calls."),
    yes: bool = typer.Option(False, "--yes", help="Skip the confirmation before the server is run in the sandbox."),
    out: Path | None = typer.Option(None, "--out", help="Output directory (default: out_dir from the config)."),
    fail_on: str = typer.Option("do_not_use", "--fail-on", help="caution | do_not_use: verdict that makes the exit code non-zero."),
    surface: Path | None = typer.Option(None, "--surface", help="Analyze a saved surface JSON; the server is not run."),
) -> None:
    """Scan an MCP server in a sandbox and report what it does, with evidence."""
    _run_scan(_load(config), static_only=static_only, yes=yes, out=out, fail_on=fail_on, surface=surface)


@app.command()
def quick(
    target: str = typer.Argument(..., help="A server directory, or npm:<package>[@version] / pypi:<package>[==version]."),
    static_only: bool = typer.Option(False, "--static-only", help="Enumerate in the sandbox but make no tool calls."),
    yes: bool = typer.Option(False, "--yes", help="Skip the confirmation before the server is run in the sandbox."),
    out: Path | None = typer.Option(None, "--out", help="Output directory (default: out/quick-<name>/)."),
    fail_on: str = typer.Option("do_not_use", "--fail-on", help="caution | do_not_use: verdict that makes the exit code non-zero."),
    command: str | None = typer.Option(None, "--command", help="Command that starts the server inside the container, if the guess is wrong."),
) -> None:
    """Scan a server without writing a config: build a default one and run `scan`."""
    try:
        data = build_quick_config(target, command=shlex.split(command) if command else None)
        cfg = parse_config(data, Path.cwd())
    except (QuickError, ConfigError) as e:
        raise _fail(str(e))
    console.print(f"[bold]Generated config:[/bold] {cfg.server.source.type} source, runtime {cfg.runtime}, command {' '.join(cfg.server.command)}", markup=True)
    _run_scan(cfg, static_only=static_only, yes=yes, out=out, fail_on=fail_on, surface=None)


def _run_scan(cfg: ScanConfig, *, static_only: bool, yes: bool, out: Path | None, fail_on: str, surface: Path | None) -> None:
    if fail_on not in ("caution", "do_not_use"):
        raise _fail("--fail-on must be 'caution' or 'do_not_use'")
    out_dir = (out or cfg.out_path).resolve()
    redactor = Redactor([cfg.config_dir, out_dir, cfg.source_path or ""])
    llm, llm_note = make_llm(cfg, redactor)
    started = time.time()

    if surface is not None:
        try:
            found = load_surface(surface)
        except SandboxError as e:
            raise _fail(str(e))
        console.print("[yellow]saved surface supplied: the server was not run, static rules only[/yellow]")
        static = static_analysis(cfg, found, llm)
        result = build_result(cfg, "n/a", found, static, mode="static", started=started, server_run=False)
        attach_llm_info(result, cfg, llm, llm_note)
        _finish(result, found, out_dir, redactor, fail_on)
        return

    ok, info = docker_available()
    if not ok:
        raise _fail(f"docker unavailable: {info}")

    mode = "static" if (static_only or cfg.scan.mode == "static" or not cfg.scan.dynamic.enabled) else "full"
    console.print(f"[bold]About to scan:[/bold] {cfg.name}", markup=True)
    console.print(f"  source   : {cfg.server.source.type} {cfg.source_path or cfg.server.source.package}", markup=False)
    console.print(f"  runtime  : {cfg.runtime}; command inside the container: {' '.join(cfg.server.command)}", markup=False)
    console.print("  sandbox  : the image build has network access (dependency install only); the run has --network none,", markup=False)
    console.print("             read-only root, no capabilities, non-root user, 512m memory, 1 cpu, only fake secrets", markup=False)
    console.print(f"  mode     : {'full (static and dynamic)' if mode == 'full' else 'static only (no tool calls)'}", markup=False)
    if not yes and not typer.confirm("Run the server inside the sandbox now?", default=False):
        raise _fail("aborted: nothing was run")

    nonce = new_nonce()
    save_run_state(out_dir, nonce)
    sandbox = Sandbox(cfg, nonce, out_dir)
    try:
        t0 = time.time()
        console.print("[1/6] Building sandbox image ... ", end="", markup=False)
        sandbox.prepare()
        console.print(f"ok ({'built' if sandbox.built_now else 'cached'}, {time.time() - t0:.0f}s)", markup=False)
        if sandbox.monitor.note:
            console.print(f"      monitor: {sandbox.monitor.note}", markup=False)
        _step(2, f"Planting honeytokens (nonce {nonce})", "ok")

        def connected(name: str, version: str | None) -> None:
            _step(3, "Connecting (stdio)", f"ok server={name} {version or ''}".rstrip())

        data = run_server(cfg, sandbox, nonce, probe=(mode == "full"), on_connected=connected)
        assert data.surface is not None

        if mode == "full":
            static, dyn, snap_findings = full_analysis(cfg, nonce, data, sandbox, llm)
        else:
            static, dyn, snap_findings = static_analysis(cfg, data.surface, llm), None, []
        result = build_result(
            cfg, nonce, data.surface, static, mode=mode, data=data, dyn=dyn, snapshot_findings=snap_findings,
            monitor_note=sandbox.monitor.note, timed_out=sandbox.timed_out, started=started,
        )
        attach_llm_info(result, cfg, llm, llm_note)
        _report_steps(result, mode, static_count=len(static.findings), dyn_count=len(dyn.findings) if dyn else 0,
                      snap_count=len(snap_findings))
    except SandboxError as e:
        console.print()
        raise _fail(str(e))
    except KeyboardInterrupt:
        err_console.print("[red]interrupted: removing the sandbox container[/red]")
        raise typer.Exit(130)
    finally:
        sandbox.cleanup()

    _finish(result, data.surface, out_dir, redactor, fail_on)


def _report_steps(result: ScanResult, mode: str, *, static_count: int, dyn_count: int, snap_count: int) -> None:
    _step(4, "Static analysis", f"{static_count + snap_count} findings")
    cov = result.coverage
    if mode != "full":
        _step(5, "Dynamic probing", "skipped (static only)")
        _step(6, "Rug-pull recheck", "skipped (static only)")
        return
    tools = cov["tools_called"]
    _step(5, f"Dynamic probing ({tools} {'tool' if tools == 1 else 'tools'}, {cov['calls_made']} calls)", f"{dyn_count} {'finding' if dyn_count == 1 else 'findings'}")
    changed = [f for f in result.findings if f.rule_id == "DY-004"]
    if changed:
        _step(6, "Rug-pull recheck", f"CHANGED ({len(changed)} tool(s))")
    elif "after_delay" in cov["snapshots"]:
        _step(6, "Rug-pull recheck", "no change")
    else:
        _step(6, "Rug-pull recheck", "not completed")


# --------------------------------------------------------------------------- report


@app.command()
def report(
    out: Path = typer.Option(Path("out"), "--out", help="Directory that holds results.json"),
    open_browser: bool = typer.Option(False, "--open", help="Open the report in the default browser."),
) -> None:
    """Re-render report.html from results.json."""
    try:
        load_result(out / "results.json")
    except SandboxError as e:
        raise _fail(str(e))
    path = render_file(out / "results.json", out / "report.html")
    console.print(f"Report written to {path}", markup=False)
    if open_browser:
        webbrowser.open(path.resolve().as_uri())
