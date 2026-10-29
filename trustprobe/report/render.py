"""Render results.json into one self-contained report.html (inline CSS and JS, no external requests)."""

from __future__ import annotations

import difflib
import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
from markupsafe import Markup, escape

from trustprobe.scoring import VERDICT_LABELS, confidence_rank, severity_rank
from trustprobe.models import Confidence, Severity

TEMPLATE_DIR = Path(__file__).parent / "templates"
REPORT_TITLE = "TrustProbe"  # the one place the product name appears in the report (see BRD section 2)

DISCLAIMER = (
    "This report describes what TrustProbe observed in the scenarios it ran. It is not a guarantee that "
    "the server is safe. Servers can behave differently later, on other inputs, or when they detect "
    "analysis. Review the coverage section before relying on this result."
)
CAPABILITY_ORDER = ["filesystem", "network", "shell", "database", "secrets"]
VERDICT_CLASS = {"do_not_use": "bad", "use_with_caution": "warn", "no_issues_found": "good"}


def _mark(text: str, matched: str | None) -> Markup:
    """Escape `text` and highlight every occurrence of `matched`."""
    if not matched or matched not in text:
        return escape(text)
    parts = text.split(matched)
    return Markup(f"<mark>{escape(matched)}</mark>").join(escape(p) for p in parts)


def diff_rows(unified: str) -> list[tuple[str, str, str]]:
    """Unified diff -> side-by-side rows of (old line, new line, kind) with kind in same/changed/removed/added."""
    rows: list[tuple[str, str, str]] = []
    removed: list[str] = []
    added: list[str] = []

    def flush() -> None:
        for old, new in _pair(removed, added):
            kind = "changed" if old is not None and new is not None else ("removed" if old is not None else "added")
            rows.append((old or "", new or "", kind))
        removed.clear()
        added.clear()

    for line in unified.splitlines():
        if line.startswith(("---", "+++", "@@")):
            continue
        if line.startswith("-"):
            removed.append(line[1:])
        elif line.startswith("+"):
            added.append(line[1:])
        else:
            flush()
            rows.append((line[1:], line[1:], "same"))
    flush()
    return rows


def _pair(old: list[str], new: list[str]):
    for i in range(max(len(old), len(new))):
        yield (old[i] if i < len(old) else None, new[i] if i < len(new) else None)


def reproduce(finding: dict, inventory: dict) -> str:
    """The exact MCP request that shows this finding."""
    target = finding["target"]
    for ev in finding["evidence"]:
        if ev.get("tool") and ev.get("arguments") is not None and ev["kind"] == "tool_call":
            req = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": ev["tool"], "arguments": ev["arguments"]}}
            return json.dumps(req, ensure_ascii=False)
    if any(t["name"] == target for t in inventory.get("tools", [])):
        return json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}) + f"\n// then check the entry named {target!r}"
    for p in inventory.get("prompts", []):
        if p["name"] == target:
            return json.dumps({"jsonrpc": "2.0", "id": 1, "method": "prompts/get", "params": {"name": target, "arguments": {}}})
    for r in inventory.get("resources", []):
        if r["name"] == target:
            return json.dumps({"jsonrpc": "2.0", "id": 1, "method": "resources/read", "params": {"uri": r["uri"]}})
    return json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}) + "\n// the finding concerns the server as a whole"


def _env() -> Environment:
    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=select_autoescape(["html", "j2"]))
    env.filters["mark"] = _mark
    env.filters["diff_rows"] = diff_rows
    return env


def render_report(data: dict) -> str:
    """`data` is the parsed results.json."""
    inventory = data["meta"].get("inventory", {})
    findings = sorted(
        data["findings"],
        key=lambda f: (-severity_rank(Severity(f["severity"])), -confidence_rank(Confidence(f["confidence"])), f["id"]),
    )
    for i, f in enumerate(findings, 1):
        f["anchor"] = f"f{i}"
        f["repro"] = reproduce(f, inventory)

    by_target: dict[str, list[dict]] = {}
    for f in findings:
        by_target.setdefault(f["target"], []).append(f)

    cov = data["coverage"]
    caps = {c: ("observed" if c in cov.get("capabilities_observed", []) else "inferred" if c in cov.get("capabilities_inferred", []) else "none")
            for c in CAPABILITY_ORDER}
    remediation: dict[str, dict] = {}
    for f in findings:
        entry = remediation.setdefault(f["rule_id"], {"rule_id": f["rule_id"], "title": f["title"], "text": f["remediation"], "targets": []})
        if f["target"] not in entry["targets"]:
            entry["targets"].append(f["target"])

    counts = {s.value: sum(1 for f in findings if f["severity"] == s.value) for s in sorted(Severity, key=severity_rank, reverse=True)}
    template = _env().get_template("report.html.j2")
    return template.render(
        title=REPORT_TITLE,
        data=data,
        meta=data["meta"],
        cov=cov,
        findings=findings,
        by_target=by_target,
        inventory=inventory,
        capabilities=caps,
        remediation=list(remediation.values()),
        counts=counts,
        phases=sorted({f["phase"] for f in findings}),
        categories=sorted({f["category"] for f in findings}),
        verdict_label=VERDICT_LABELS[data["verdict"]],
        verdict_class=VERDICT_CLASS[data["verdict"]],
        disclaimer=DISCLAIMER,
    )


def render_file(results_json: Path, report_html: Path) -> Path:
    report_html.write_text(render_report(json.loads(results_json.read_text(encoding="utf-8"))), encoding="utf-8")
    return report_html
