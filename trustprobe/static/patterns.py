"""Shared helpers for the static analyzer: surface items, schema walking, text and Unicode
helpers, and the Python functions behind `type: custom` rules.

A custom rule names one of the functions registered here. Each takes (rule, ctx) and
returns a list of `Hit`s; the analyzer turns hits into findings.
"""

from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import yaml

from trustprobe.models import Evidence, ServerSurface, Severity

EXCERPT_LIMIT = 300
KNOWN_TOOLS_FILE = Path(__file__).parent / "known_tools.yaml"
CAPABILITY_NAMES = ("filesystem", "network", "shell", "database", "secrets")


# --------------------------------------------------------------------------- data classes


@dataclass
class Item:
    """One tool, prompt or resource, with the text fields rules can look at."""

    kind: str  # "tool" | "prompt" | "resource"
    target: str  # name used in findings
    raw: dict
    fields: dict[str, list[str]] = field(default_factory=dict)


@dataclass
class Hit:
    """What a rule found on one target. The analyzer builds the Finding from it."""

    target: str
    evidence: list[Evidence]
    severity: Severity | None = None  # overrides the rule's severity
    title: str | None = None
    description: str | None = None


@dataclass
class Context:
    surface: ServerSurface
    items: list[Item]
    known_tools: set[str]
    declared_capabilities: set[str] = field(default_factory=set)
    source: dict | None = None  # {"type": "npm", "package": ..., "version": ...}; None for --surface
    capabilities: set[str] = field(default_factory=set)  # filled by the capability rule

    @property
    def tools(self) -> list[Item]:
        return [i for i in self.items if i.kind == "tool"]


CustomFn = Callable[[Any, Context], list[Hit]]
CUSTOM: dict[str, CustomFn] = {}


def custom(name: str):
    def register(fn: CustomFn) -> CustomFn:
        CUSTOM[name] = fn
        return fn

    return register


# --------------------------------------------------------------------------- text helpers


def excerpt(text: str, start: int = 0, end: int | None = None, limit: int = EXCERPT_LIMIT) -> str:
    """A short quote around [start, end), whitespace collapsed, at most `limit` characters."""
    end = len(text) if end is None else end
    lo, hi = max(0, start - 60), min(len(text), end + 120)
    out = ("..." if lo > 0 else "") + re.sub(r"\s+", " ", text[lo:hi]).strip() + ("..." if hi < len(text) else "")
    return out if len(out) <= limit else out[: limit - 3] + "..."


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def name_tokens(name: str) -> list[str]:
    """'readFile', 'read_file' and 'read-file' all give ['read', 'file']."""
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    return [t for t in re.split(r"[^A-Za-z0-9]+", spaced.lower()) if t]


def parse_ranges(specs: list[str]) -> list[tuple[int, int]]:
    """['200B-200F', 'FEFF'] -> [(0x200B, 0x200F), (0xFEFF, 0xFEFF)]."""
    out = []
    for spec in specs:
        lo, _, hi = spec.partition("-")
        out.append((int(lo, 16), int(hi or lo, 16)))
    return out


def in_ranges(ch: str, ranges: list[tuple[int, int]]) -> bool:
    cp = ord(ch)
    return any(lo <= cp <= hi for lo, hi in ranges)


def reveal(text: str, ranges: list[tuple[int, int]]) -> str:
    """Make invisible characters visible as <U+200B> for evidence."""
    return "".join(f"<U+{ord(c):04X}>" if in_ranges(c, ranges) else c for c in text)


def load_known_tools() -> set[str]:
    data = yaml.safe_load(KNOWN_TOOLS_FILE.read_text(encoding="utf-8")) or {}
    return {n.lower() for n in data.get("names", [])}


# --------------------------------------------------------------------------- schema helpers


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [s for v in value for s in _strings(v)]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _strings(v)]
    return []


def schema_nodes(schema: Any, depth: int = 0):
    """Every sub-schema dict, at any depth (properties, items, anyOf/oneOf/allOf, $defs)."""
    if not isinstance(schema, dict) or depth > 8:
        return
    yield schema
    for key in ("properties", "$defs", "definitions", "patternProperties"):
        val = schema.get(key)
        if isinstance(val, dict):
            for sub in val.values():
                yield from schema_nodes(sub, depth + 1)
    for key in ("items", "additionalProperties", "not", "if", "then", "else"):
        yield from schema_nodes(schema.get(key), depth + 1)
    for key in ("anyOf", "oneOf", "allOf", "prefixItems"):
        val = schema.get(key)
        if isinstance(val, list):
            for sub in val:
                yield from schema_nodes(sub, depth + 1)


def iter_properties(schema: Any, depth: int = 0):
    """Yield (name, sub-schema) for every named property at any depth."""
    for node in schema_nodes(schema, depth):
        props = node.get("properties")
        if isinstance(props, dict):
            for name, sub in props.items():
                yield name, sub if isinstance(sub, dict) else {}


def schema_values(schema: Any) -> list[str]:
    """Strings an agent may read as instructions: defaults, enums, examples, consts, titles."""
    out: list[str] = []
    for node in schema_nodes(schema):
        for key in ("default", "enum", "examples", "const", "title"):
            out += _strings(node.get(key))
    return out


def param_descriptions(schema: Any) -> list[str]:
    return [d for node in schema_nodes(schema) for d in _strings(node.get("description"))]


def is_string_schema(sub: dict) -> bool:
    t = sub.get("type")
    if t == "string" or (isinstance(t, list) and "string" in t):
        return True
    return any(isinstance(s, dict) and is_string_schema(s) for s in sub.get("anyOf", []) + sub.get("oneOf", []))


# --------------------------------------------------------------------------- building items


def build_items(surface: ServerSurface) -> list[Item]:
    items: list[Item] = []
    for t in surface.tools:
        schema = t.get("inputSchema") or {}
        items.append(Item("tool", t.get("name", ""), t, {
            "tool.name": [t.get("name", "")],
            "tool.description": [t.get("description") or ""],
            "tool.param_names": [n for n, _ in iter_properties(schema)],
            "tool.param_descriptions": param_descriptions(schema),
            "tool.schema_values": schema_values(schema),
        }))
    for p in surface.prompts:
        arg_docs = [a.get("description") or "" for a in (p.get("arguments") or [])]
        items.append(Item("prompt", p.get("name", ""), p, {
            "prompt.description": [p.get("description") or "", *arg_docs],
            "prompt.messages": list(p.get("messages") or []),
        }))
    for r in surface.resources:
        uri = r.get("uri", "")
        items.append(Item("resource", r.get("name") or uri, r, {
            "resource.description": [r.get("description") or ""],
            "resource.content": [surface.resource_contents.get(uri, "")],
        }))
    for r in surface.resource_templates:
        items.append(Item("resource", r.get("name") or r.get("uriTemplate", ""), r, {
            "resource.description": [r.get("description") or ""],
            "resource.content": [],
        }))
    return items


def evidence_for(item: Item, summary: str, detail: str, matched: str | None = None) -> Evidence:
    return Evidence(kind="text", summary=summary, detail=detail[:2000], tool=item.target if item.kind == "tool" else None, matched=matched)


# --------------------------------------------------------------------------- custom rules


@custom("cross_tool_manipulation")
def cross_tool_manipulation(rule: Any, ctx: Context) -> list[Hit]:
    """TP-006: a description names another tool and uses imperative words about it."""
    imperatives = rule.options.get("imperatives", [])
    imp_rx = re.compile(r"\b(" + "|".join(map(re.escape, imperatives)) + r")\b", re.IGNORECASE)
    own_names = {t.target.lower() for t in ctx.tools}
    hits = []
    for item in ctx.tools:
        text = "\n".join(item.fields["tool.description"] + item.fields["tool.param_descriptions"])
        imp = imp_rx.search(text)
        if not imp:
            continue
        for other in sorted((own_names | ctx.known_tools) - {item.target.lower()}):
            m = re.search(rf"(?<![A-Za-z0-9_]){re.escape(other)}(?![A-Za-z0-9_])", text, re.IGNORECASE)
            if m:
                hits.append(Hit(item.target, [evidence_for(
                    item, f"description names tool '{other}' with imperative '{imp.group(0)}'",
                    excerpt(text, min(m.start(), imp.start()), max(m.end(), imp.end())), other)]))
                break
    return hits


@custom("capability_inference")
def capability_inference(rule: Any, ctx: Context) -> list[Hit]:
    """PM-002: infer filesystem/network/shell/database/secrets from names and descriptions."""
    keywords: dict[str, list[str]] = rule.options.get("keywords", {})
    rx = {cap: re.compile(r"\b(?:" + "|".join(re.escape(k) for k in kws) + r")s?\b", re.IGNORECASE) for cap, kws in keywords.items()}
    hits = []
    for item in ctx.tools:
        text = " ".join([" ".join(name_tokens(item.target)), *item.fields["tool.description"]])
        undeclared, found = [], []
        for cap, pattern in rx.items():
            m = pattern.search(text)
            if not m:
                continue
            ctx.capabilities.add(cap)
            found.append(f"{cap} (from '{m.group(0)}')")
            if cap not in ctx.declared_capabilities:
                undeclared.append(cap)
        if not found:
            continue
        hits.append(Hit(
            item.target,
            [evidence_for(item, "capabilities inferred from the tool name and description", "; ".join(found))],
            severity=Severity.low if undeclared else Severity.info,
            title="Capability not declared by the operator" if undeclared else "Capability inferred (declared by the operator)",
            description=(f"The tool appears to use: {', '.join(undeclared)}, which the operator did not list in declared_capabilities."
                         if undeclared else "The tool's capabilities match what the operator declared."),
        ))
    return hits


@custom("free_form_input")
def free_form_input(rule: Any, ctx: Context) -> list[Hit]:
    """PM-003: additionalProperties true, or a schema that says nothing about its input."""
    hits = []
    for item in ctx.tools:
        schema = item.raw.get("inputSchema")
        why = None
        if isinstance(schema, dict) and schema.get("additionalProperties") is True:
            why = "additionalProperties is true"
        elif not isinstance(schema, dict) or not ({"properties", "required", "patternProperties", "oneOf", "anyOf", "allOf", "enum"} & set(schema)):
            why = "the input schema declares no properties or constraints"
        if why:
            hits.append(Hit(item.target, [evidence_for(item, f"free-form input: {why}", json.dumps(schema, ensure_ascii=False)[:300])]))
    return hits


@custom("destructive_without_annotation")
def destructive_without_annotation(rule: Any, ctx: Context) -> list[Hit]:
    """PM-004: a delete/remove/drop/kill/format/overwrite tool with no destructiveHint."""
    words = set(rule.options.get("words", []))
    hits = []
    for item in ctx.tools:
        hit_words = [t for t in name_tokens(item.target) if t in words]
        annotations = item.raw.get("annotations") or {}
        if hit_words and "destructiveHint" not in annotations:
            hits.append(Hit(item.target, [evidence_for(item, f"name contains '{hit_words[0]}' but no destructiveHint annotation", item.target, hit_words[0])]))
    return hits


_SCRIPTS = ("LATIN", "CYRILLIC", "GREEK")


def _scripts(name: str) -> set[str]:
    out = set()
    for ch in name:
        if ch.isalpha():
            first = unicodedata.name(ch, "").split(" ")[0]
            if first in _SCRIPTS:
                out.add(first)
    return out


@custom("confusable_names")
def confusable_names(rule: Any, ctx: Context) -> list[Hit]:
    """SH-002: names equal after NFKC + lowercase, or mixing Latin/Cyrillic/Greek letters."""
    hits, seen = [], {}
    for item in ctx.tools:
        scripts = _scripts(item.target)
        if len(scripts) > 1:
            hits.append(Hit(item.target, [evidence_for(item, f"name mixes scripts: {', '.join(sorted(scripts))}", ascii(item.target), item.target)]))
        norm = unicodedata.normalize("NFKC", item.target).lower()
        if norm in seen:
            hits.append(Hit(item.target, [evidence_for(item, f"name is equal to '{seen[norm]}' after normalization", f"{ascii(seen[norm])} vs {ascii(item.target)}", norm)]))
        else:
            seen[norm] = item.target
    return hits


@custom("prompt_tool_directive")
def prompt_tool_directive(rule: Any, ctx: Context) -> list[Hit]:
    """PR-002: a prompt message tells the model to call a tool."""
    pats = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in rule.options.get("patterns", [])]
    names = {t.target for t in ctx.tools} | ctx.known_tools
    invoke = re.compile(r"\binvoke\s+(?:the\s+)?([A-Za-z0-9_\-]+)", re.IGNORECASE)
    hits = []
    for item in (i for i in ctx.items if i.kind == "prompt"):
        found = []
        for text in item.fields["prompt.messages"]:
            for rx in pats:
                m = rx.search(text)
                if m:
                    found.append(evidence_for(item, "message directs the model to call a tool", excerpt(text, m.start(), m.end()), m.group(0)))
            for m in invoke.finditer(text):
                if m.group(1).lower() in {n.lower() for n in names}:
                    found.append(evidence_for(item, f"message tells the model to invoke '{m.group(1)}'", excerpt(text, m.start(), m.end()), m.group(0)))
        if found:
            hits.append(Hit(item.target, found[:6]))
    return hits


_SENSITIVE_URI = re.compile(r"/etc/|\.ssh|\.aws|\.env|id_rsa", re.IGNORECASE)
_WIDE_TEMPLATE = re.compile(r"^file:///?\{\+?[^}/]+\}", re.IGNORECASE)


@custom("sensitive_resource_uri")
def sensitive_resource_uri(rule: Any, ctx: Context) -> list[Hit]:
    """RS-002: file:// URIs to credentials or system files, and file:// templates open to any path."""
    hits = []
    for item in (i for i in ctx.items if i.kind == "resource"):
        uri = item.raw.get("uri") or item.raw.get("uriTemplate") or ""
        if not uri.lower().startswith("file://"):
            continue
        if _SENSITIVE_URI.search(uri):
            hits.append(Hit(item.target, [evidence_for(item, "resource URI points at a sensitive file", uri, uri)], severity=Severity.high))
        elif _WIDE_TEMPLATE.match(uri):
            hits.append(Hit(item.target, [evidence_for(item, "template lets the caller pick any file path", uri, uri)], severity=Severity.medium))
    return hits


@custom("missing_identity")
def missing_identity(rule: Any, ctx: Context) -> list[Hit]:
    """MD-001: no server name or version in the handshake."""
    name, version = (ctx.surface.server_name or "").strip(), (ctx.surface.server_version or "").strip()
    missing = [label for label, value in (("name", name if name.lower() != "unknown" else ""), ("version", version)) if not value]
    if not missing:
        return []
    return [Hit("server", [Evidence(kind="text", summary=f"handshake has no server {' or '.join(missing)}", detail=f"name={name!r} version={version!r}")])]


_EXACT_VERSION = re.compile(r"^v?\d+(\.\d+)*([-+.][0-9A-Za-z.]+)?$")


@custom("unpinned_source")
def unpinned_source(rule: Any, ctx: Context) -> list[Hit]:
    """MD-002: an npm or PyPI source without an exact version."""
    src = ctx.source
    if not src or src.get("type") not in ("npm", "pypi"):
        return []
    version = (src.get("version") or "").strip()
    if version and _EXACT_VERSION.match(version):
        return []
    shown = f"{src.get('package')}@{version}" if version else str(src.get("package"))
    return [Hit("server", [Evidence(kind="text", summary="package version is not pinned", detail=shown, matched=version or None)])]
