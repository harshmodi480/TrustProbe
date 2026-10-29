"""Test input generation: benign arguments from a tool's JSON schema, and hostile payloads.

Everything is generated in a fixed order so the same server and nonce always get the same
calls. Only the `.invalid` top-level domain is ever used for hostnames.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

# Hostile inputs, in priority order (BRD 8.5). `{n}` is replaced by the scan nonce.
# $((6*7)) is deliberate: a server that only echoes the text returns "$((6*7))", while one that
# runs it in a shell returns "42", so TPROBE-<nonce>-42 can only appear if the payload executed.
HOSTILE_KINDS: list[tuple[str, str]] = [
    ("path_traversal", "../../../../../../etc/passwd"),
    ("traversal_encoded", "..%2f..%2f..%2f..%2fetc%2fpasswd"),
    ("shell_semicolon", "test; echo TPROBE-{n}-$((6*7))"),
    ("shell_substitution", "$(echo TPROBE-{n}-$((6*7)))"),
    ("shell_backticks", "`echo TPROBE-{n}-$((6*7))`"),
    ("shell_and", "test && echo TPROBE-{n}-$((6*7))"),
    ("sql", "' OR '1'='1' --"),
    ("oversized", "A" * 100_000),
    ("special_chars", "a\x00b\nc \U0001f600 ' \" { } {{x}} ${x} %s"),
]
SHELL_KINDS = {"shell_semicolon", "shell_substitution", "shell_backticks", "shell_and"}
TRAVERSAL_KINDS = {"path_traversal", "traversal_encoded"}

MIN_CALLS_PER_TOOL = 4  # rug pulls often trigger on a call count, so every tool is called a few times


@dataclass(frozen=True)
class TestInput:
    __test__ = False  # not a pytest test class

    label: str  # "benign", "benign-full", "boundary-max", "hostile:sql", ...
    arguments: dict
    hostile: bool = False
    kind: str | None = None  # hostile kind
    param: str | None = None  # parameter that carries the payload

    @property
    def payload(self) -> str | None:
        return self.arguments.get(self.param) if self.param else None


def hostile_payloads(nonce: str) -> list[tuple[str, str]]:
    return [(kind, value.replace("{n}", nonce)) for kind, value in HOSTILE_KINDS]


# --------------------------------------------------------------------------- benign values


def _branch(schema: dict) -> dict:
    """First non-null alternative of an anyOf/oneOf."""
    for key in ("anyOf", "oneOf"):
        for sub in schema.get(key, []) or []:
            if isinstance(sub, dict) and sub.get("type") != "null":
                return {**{k: v for k, v in schema.items() if k not in ("anyOf", "oneOf")}, **sub}
    return schema


def _type(schema: dict) -> str | None:
    t = schema.get("type")
    if isinstance(t, list):
        t = next((x for x in t if x != "null"), None)
    if t:
        return t
    if "properties" in schema:
        return "object"
    if "items" in schema:
        return "array"
    return None


def _string_value(schema: dict, name: str) -> str:
    fmt = schema.get("format")
    lowered = name.lower()
    if fmt in ("uri", "url"):
        value = "http://example.invalid/test"
    elif fmt == "email":
        value = "test@example.invalid"
    elif fmt == "date":
        value = "2025-01-01"
    elif fmt == "date-time":
        value = "2025-01-01T00:00:00Z"
    elif any(h in lowered for h in ("path", "file", "filename", "dir")):
        value = "/workspace/sample.txt"
    elif any(h in lowered for h in ("city", "location")):
        value = "London"
    else:
        value = "test"
    min_len = schema.get("minLength")
    if isinstance(min_len, int) and len(value) < min_len:
        value = (value * (min_len // len(value) + 1))[:min_len]
    max_len = schema.get("maxLength")
    if isinstance(max_len, int) and len(value) > max_len:
        value = value[:max_len]
    return value


def _number_value(schema: dict, variant: str, integer: bool):
    lo = schema.get("minimum")
    if lo is None and "exclusiveMinimum" in schema:
        lo = schema["exclusiveMinimum"] + 1
    hi = schema.get("maximum")
    if hi is None and "exclusiveMaximum" in schema:
        hi = schema["exclusiveMaximum"] - 1
    if variant == "max":
        value = hi if hi is not None else (lo + 100 if lo is not None else 100)
    elif variant == "mid":
        value = 0
    else:
        value = lo if lo is not None else 1
    if lo is not None:
        value = max(value, lo)
    if hi is not None:
        value = min(value, hi)
    return int(value) if integer else value


def benign_value(schema: dict, name: str = "", variant: str = "default"):
    """A schema-valid, harmless value. `variant`: default | max | mid | true | enum:<index>."""
    if not isinstance(schema, dict):
        return "test"
    schema = _branch(schema)
    if "const" in schema:
        return schema["const"]
    if schema.get("enum"):
        idx = int(variant.split(":")[1]) if variant.startswith("enum:") else 0
        return schema["enum"][min(idx, len(schema["enum"]) - 1)]
    t = _type(schema)
    if t == "string":
        return _string_value(schema, name)
    if t in ("integer", "number"):
        return _number_value(schema, variant, t == "integer")
    if t == "boolean":
        return variant == "true"
    if t == "null":
        return None
    if t == "array":
        count = max(int(schema.get("minItems") or 0), 1)
        return [benign_value(schema.get("items") or {}, name, variant) for _ in range(count)]
    if t == "object":
        return build_arguments(schema, include_optional=False)
    return "test"


def build_arguments(schema: dict, *, include_optional: bool, variant: str = "default", overrides: dict | None = None) -> dict:
    """Arguments for an object schema: required properties, plus the optional ones if asked."""
    props = (schema or {}).get("properties") or {}
    required = set((schema or {}).get("required") or [])
    args: dict = {}
    for name, sub in props.items():
        if include_optional or name in required:
            args[name] = benign_value(sub if isinstance(sub, dict) else {}, name, variant)
    if overrides:
        args.update(overrides)
    return args


# --------------------------------------------------------------------------- plan


def _is_plain_string(sub: dict) -> bool:
    sub = _branch(sub) if isinstance(sub, dict) else {}
    return _type(sub) == "string" and not sub.get("enum") and "const" not in sub


def plan_for_tool(tool: dict, nonce: str, *, max_calls: int) -> list[TestInput]:
    """The ordered list of calls for one tool, at most `max_calls` long.

    Order: benign with required fields only, benign with every field, hostile inputs (one
    string parameter at a time, kinds in priority order across parameters), numeric boundaries,
    boolean and enum variants. Tools that end up with fewer than 4 calls are padded with
    repeats of the first benign call.
    """
    schema = tool.get("inputSchema") or {}
    props: dict = schema.get("properties") or {}
    plan: list[TestInput] = []
    seen: set[str] = set()

    def add(ti: TestInput) -> None:
        key = json.dumps(ti.arguments, sort_keys=True, default=str)
        if key not in seen:
            seen.add(key)
            plan.append(ti)

    add(TestInput("benign", build_arguments(schema, include_optional=False)))
    add(TestInput("benign-full", build_arguments(schema, include_optional=True)))

    string_params = [n for n, sub in props.items() if _is_plain_string(sub)]
    for kind, value in hostile_payloads(nonce):
        for param in string_params:
            add(TestInput(f"hostile:{kind}", build_arguments(schema, include_optional=True, overrides={param: value}), True, kind, param))

    numeric = [n for n, sub in props.items() if _type(_branch(sub) if isinstance(sub, dict) else {}) in ("integer", "number")]
    if numeric:
        for variant in ("max", "mid"):
            add(TestInput(f"boundary-{variant}", build_arguments(schema, include_optional=True, variant=variant)))

    for name, sub in props.items():
        sub = _branch(sub) if isinstance(sub, dict) else {}
        if _type(sub) == "boolean":
            add(TestInput(f"bool-{name}-true", build_arguments(schema, include_optional=True, overrides={name: True})))
        for i in range(1, len(sub.get("enum") or [])):
            add(TestInput(f"enum-{name}-{i}", build_arguments(schema, include_optional=True, overrides={name: sub["enum"][i]})))

    plan = plan[:max_calls]
    repeats = 0
    while len(plan) < min(MIN_CALLS_PER_TOOL, max_calls):
        repeats += 1
        first = plan[0]
        plan.append(TestInput(f"repeat-{repeats}", dict(first.arguments)))
    return plan


def expand_template(uri_template: str, value: str = "sample.txt") -> str:
    """Fill every {variable} (including {+var}) of a resource template with a harmless value."""
    return re.sub(r"\{[^}]*\}", value, uri_template)
