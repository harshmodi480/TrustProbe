"""Static analyzer: load YAML rules and run them over an enumerated ServerSurface.

Nothing here calls a tool. A new rule is one YAML entry in `static/rules/`; rules that
need code use `type: custom` and name a function registered in `static/patterns.py`.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Literal

import yaml
from pydantic import BaseModel, ConfigDict, ValidationError

from trustprobe.models import Category, Confidence, Evidence, Finding, ServerSurface, Severity
from trustprobe.scoring import severity_rank
from trustprobe.static.patterns import (
    CUSTOM,
    Context,
    Hit,
    Item,
    build_items,
    evidence_for,
    excerpt,
    in_ranges,
    is_string_schema,
    iter_properties,
    levenshtein,
    load_known_tools,
    parse_ranges,
    reveal,
    schema_nodes,
)

RULES_DIR = Path(__file__).parent / "rules"


class RuleError(Exception):
    """A rule file is malformed. The message names the file and rule."""


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    title: str
    category: Category
    severity: Severity
    confidence: Confidence
    type: Literal["regex", "unicode", "schema_param", "length", "name_similarity", "custom"]
    description: str
    impact: str
    remediation: str
    fields: list[str] = []
    patterns: list[str] = []  # regex rules; case-insensitive and DOTALL unless case_sensitive
    patterns_from: list[str] = []  # also use the patterns of these rule ids
    min_matches: int = 1  # distinct patterns that must match
    case_sensitive: bool = False
    ranges: list[str] = []  # unicode rules: hex ranges such as "200B-200F"
    thresholds: list[dict] = []  # length rules: [{over: 1500, severity: low}, ...]
    param_rules: list[dict] = []  # schema_param rules: [{names: [...], severity: high}, ...]
    constraint_keys: list[str] = []  # schema_param rules: keys that make a parameter "constrained"
    max_distance: int = 2  # name_similarity rules
    min_length: int = 5  # name_similarity rules: shorter names are never flagged
    function: str | None = None  # custom rules: name in patterns.CUSTOM
    options: dict = {}  # custom rules: free-form settings


@dataclass
class AnalysisResult:
    findings: list[Finding] = field(default_factory=list)
    capabilities: list[str] = field(default_factory=list)
    rules_run: list[str] = field(default_factory=list)
    rule_errors: dict[str, str] = field(default_factory=dict)


# --------------------------------------------------------------------------- loading


def load_rules(rules_dir: Path = RULES_DIR, extra_dirs: tuple[Path, ...] = ()) -> list[Rule]:
    rules: list[Rule] = []
    seen: dict[str, str] = {}
    for directory in (rules_dir, *extra_dirs):
        for path in sorted(Path(directory).glob("*.yaml")):
            try:
                entries = yaml.safe_load(path.read_text(encoding="utf-8")) or []
            except yaml.YAMLError as e:
                raise RuleError(f"{path.name}: invalid YAML: {e}") from e
            if not isinstance(entries, list):
                raise RuleError(f"{path.name}: expected a list of rules")
            for entry in entries:
                try:
                    rule = Rule.model_validate(entry)
                except ValidationError as e:
                    rid = entry.get("id", "?") if isinstance(entry, dict) else "?"
                    problems = "; ".join(f"{'.'.join(map(str, x['loc']))}: {x['msg']}" for x in e.errors())
                    raise RuleError(f"{path.name}: rule {rid}: {problems}") from e
                if rule.id in seen:
                    raise RuleError(f"{path.name}: rule id {rule.id} is already defined in {seen[rule.id]}")
                if rule.type == "custom" and rule.function not in CUSTOM:
                    raise RuleError(f"{path.name}: rule {rule.id}: unknown custom function {rule.function!r}")
                seen[rule.id] = path.name
                rules.append(rule)
    known = {r.id for r in rules}
    for r in rules:
        for ref in r.patterns_from:
            if ref not in known:
                raise RuleError(f"rule {r.id}: patterns_from references unknown rule {ref}")
    return rules


def rule_patterns(rule_ids: list[str]) -> list[re.Pattern[str]]:
    """Compiled patterns of the named rules: a regex rule's `patterns`, or a custom rule's `options.patterns`.

    Lets dynamic probes (DY-005) reuse the static detection patterns instead of copying them.
    """
    by_id = {r.id: r for r in load_rules()}
    out = []
    for rid in rule_ids:
        rule = by_id[rid]
        flags = re.DOTALL | (0 if rule.case_sensitive else re.IGNORECASE)
        out += [re.compile(p, flags) for p in [*rule.patterns, *rule.options.get("patterns", [])]]
    return out


def _patterns(rule: Rule, by_id: dict[str, Rule]) -> list[str]:
    out = list(rule.patterns)
    for ref in rule.patterns_from:
        out += by_id[ref].patterns
    return out


# --------------------------------------------------------------------------- built-in rule types


def _items_for(rule: Rule, ctx: Context) -> list[tuple[Item, list[str]]]:
    """Items that own at least one of the rule's fields, with the field names to look at."""
    out = []
    for item in ctx.items:
        names = list(item.fields) if "*" in rule.fields else [f for f in rule.fields if f in item.fields]
        if names:
            out.append((item, names))
    return out


def _regex(rule: Rule, ctx: Context, by_id: dict[str, Rule]) -> list[Hit]:
    flags = re.DOTALL | (0 if rule.case_sensitive else re.IGNORECASE)
    compiled = [re.compile(p, flags) for p in _patterns(rule, by_id)]
    hits = []
    for item, names in _items_for(rule, ctx):
        matched: set[int] = set()
        evidence: list[Evidence] = []
        for fname in names:
            for text in item.fields[fname]:
                for i, rx in enumerate(compiled):
                    m = rx.search(text)
                    if m:
                        matched.add(i)
                        evidence.append(evidence_for(item, f"{fname} matched pattern {i + 1}", excerpt(text, m.start(), m.end()), m.group(0)[:200]))
        if len(matched) >= rule.min_matches:
            hits.append(Hit(item.target, evidence[:6]))
    return hits


def _unicode(rule: Rule, ctx: Context, by_id: dict[str, Rule]) -> list[Hit]:
    ranges = parse_ranges(rule.ranges)
    hits = []
    for item, names in _items_for(rule, ctx):
        evidence = []
        for fname in names:
            for text in item.fields[fname]:
                found = sorted({ord(c) for c in text if in_ranges(c, ranges)})
                if found:
                    first = next(i for i, c in enumerate(text) if in_ranges(c, ranges))
                    shown = ", ".join(f"U+{cp:04X}" for cp in found[:8])
                    evidence.append(evidence_for(item, f"{fname} contains invisible or bidirectional characters: {shown}", reveal(excerpt(text, first, first + 1), ranges), f"U+{found[0]:04X}"))
        if evidence:
            hits.append(Hit(item.target, evidence[:6]))
    return hits


def _length(rule: Rule, ctx: Context, by_id: dict[str, Rule]) -> list[Hit]:
    steps = sorted(rule.thresholds, key=lambda t: t["over"])
    hits = []
    for item, names in _items_for(rule, ctx):
        worst: tuple[Severity, list[Evidence]] | None = None
        for fname in names:
            for text in item.fields[fname]:
                limit = next((t for t in reversed(steps) if len(text) > t["over"]), None)
                if limit is None:
                    continue
                sev = Severity(limit["severity"])
                ev = evidence_for(item, f"{fname} is {len(text)} characters (over {limit['over']})", excerpt(text, 0, 0), None)
                if worst is None or severity_rank(sev) > severity_rank(worst[0]):
                    worst = (sev, [ev])
                elif sev == worst[0]:
                    worst[1].append(ev)
        if worst:
            hits.append(Hit(item.target, worst[1][:6], severity=worst[0]))
    return hits


def _schema_param(rule: Rule, ctx: Context, by_id: dict[str, Rule]) -> list[Hit]:
    severity_by_name = {n.lower(): Severity(pr["severity"]) for pr in rule.param_rules for n in pr["names"]}
    constraint_keys = set(rule.constraint_keys)
    hits = []
    for item in ctx.tools:
        offenders: list[tuple[str, Severity, dict]] = []
        for name, sub in iter_properties(item.raw.get("inputSchema")):
            sev = severity_by_name.get(name.lower())
            constrained = any(constraint_keys & set(node) for node in schema_nodes(sub))
            if sev and is_string_schema(sub) and not constrained:
                offenders.append((name, sev, sub))
        if offenders:
            worst = max((o[1] for o in offenders), key=severity_rank)
            evidence = [evidence_for(item, f"parameter '{n}' is a string with no enum, pattern, maxLength or format",
                                     json.dumps(sub, ensure_ascii=False), n) for n, _, sub in offenders]
            hits.append(Hit(item.target, evidence[:6], severity=worst))
    return hits


def _name_similarity(rule: Rule, ctx: Context, by_id: dict[str, Rule]) -> list[Hit]:
    hits = []
    for item in ctx.tools:
        name = item.target.lower()
        if len(name) < rule.min_length or name in ctx.known_tools:
            continue
        near = sorted((levenshtein(name, k), k) for k in ctx.known_tools if abs(len(k) - len(name)) <= rule.max_distance)
        if near and 1 <= near[0][0] <= rule.max_distance:
            dist, known = near[0]
            hits.append(Hit(item.target, [evidence_for(item, f"'{item.target}' is {dist} edit(s) from the well-known tool '{known}'", f"{item.target} ~ {known}", known)]))
    return hits


Handler = Callable[[Rule, Context, dict[str, Rule]], list[Hit]]
HANDLERS: dict[str, Handler] = {
    "regex": _regex,
    "unicode": _unicode,
    "length": _length,
    "schema_param": _schema_param,
    "name_similarity": _name_similarity,
    "custom": lambda rule, ctx, by_id: CUSTOM[rule.function](rule, ctx),  # type: ignore[index]
}


# --------------------------------------------------------------------------- running


def _to_finding(rule: Rule, hit: Hit, label: str | None) -> Finding:
    evidence = [e.model_copy() for e in hit.evidence]
    if label:
        for e in evidence:
            e.summary = f"[snapshot {label}] {e.summary}"
    return Finding(
        id=f"{rule.id}:{hit.target}",
        rule_id=rule.id,
        title=hit.title or rule.title,
        category=rule.category,
        severity=hit.severity or rule.severity,
        confidence=rule.confidence,
        target=hit.target,
        phase="static",
        description=hit.description or rule.description,
        impact=rule.impact,
        remediation=rule.remediation,
        evidence=evidence,
    )


def analyze(
    surface: ServerSurface,
    *,
    declared_capabilities: tuple[str, ...] | list[str] = (),
    source: dict | None = None,
    label: str | None = None,
    tools_only: bool = False,
    rules: list[Rule] | None = None,
) -> AnalysisResult:
    """Run every static rule over the surface.

    `label` marks findings that come from a tool-list snapshot (for example "after_probes");
    `tools_only` limits the run to tool definitions, which is what a snapshot contains.
    A rule that raises is recorded in `rule_errors` and never aborts the analysis.
    """
    rules = rules if rules is not None else load_rules()
    by_id = {r.id: r for r in rules}
    if tools_only:
        surface = surface.model_copy(update={"prompts": [], "resources": [], "resource_templates": [], "resource_contents": {}})
    ctx = Context(
        surface=surface,
        items=build_items(surface),
        known_tools=load_known_tools(),
        declared_capabilities=set(declared_capabilities),
        source=source,
    )
    result = AnalysisResult()
    merged: dict[str, Finding] = {}
    for rule in rules:
        if tools_only and rule.category == Category.metadata:
            continue
        try:
            hits = HANDLERS[rule.type](rule, ctx, by_id)
        except Exception as e:  # noqa: BLE001 - a failing rule must not abort the scan
            result.rule_errors[rule.id] = f"{type(e).__name__}: {e}"
            continue
        result.rules_run.append(rule.id)
        for hit in hits:
            finding = _to_finding(rule, hit, label)
            if finding.id in merged:
                merged[finding.id].evidence += finding.evidence
            else:
                merged[finding.id] = finding
    result.findings = list(merged.values())
    result.capabilities = sorted(ctx.capabilities)
    return result
