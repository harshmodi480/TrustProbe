"""Input generation from JSON schemas. No Docker."""

import json

import pytest

from trustprobe.dynamic.inputs import (
    HOSTILE_KINDS,
    MIN_CALLS_PER_TOOL,
    benign_value,
    build_arguments,
    expand_template,
    hostile_payloads,
    plan_for_tool,
)

NONCE = "7f3a91c2"


def tool(props, required=None, name="t"):
    return {"name": name, "inputSchema": {"type": "object", "properties": props, "required": required or []}}


# ------------------------------------------------------------------ benign values (BRD 8.4 table)


@pytest.mark.parametrize("schema,name,expected", [
    ({"type": "string", "format": "uri"}, "x", "http://example.invalid/test"),
    ({"type": "string", "format": "url"}, "x", "http://example.invalid/test"),
    ({"type": "string", "format": "email"}, "x", "test@example.invalid"),
    ({"type": "string"}, "path", "/workspace/sample.txt"),
    ({"type": "string"}, "filename", "/workspace/sample.txt"),
    ({"type": "string"}, "dir", "/workspace/sample.txt"),
    ({"type": "string"}, "city", "London"),
    ({"type": "string"}, "location", "London"),
    ({"type": "string", "format": "date"}, "when", "2025-01-01"),
    ({"type": "string"}, "other", "test"),
    ({"type": "integer"}, "n", 1),
    ({"type": "number", "minimum": 5}, "n", 5),
    ({"type": "number", "minimum": -1e9, "maximum": 1e9}, "n", -1e9),
    ({"type": "integer", "minimum": 10, "maximum": 3}, "n", 3),
    ({"type": "boolean"}, "b", False),
    ({"type": "null"}, "n", None),
    ({"const": "fixed"}, "n", "fixed"),
])
def test_benign_values(schema, name, expected):
    assert benign_value(schema, name) == expected


def test_enum_takes_the_first_value_by_default_and_others_by_variant():
    schema = {"type": "string", "enum": ["a", "b", "c"]}
    assert benign_value(schema) == "a"
    assert benign_value(schema, variant="enum:2") == "c"
    assert benign_value(schema, variant="enum:9") == "c"


def test_boolean_variants():
    assert benign_value({"type": "boolean"}, variant="true") is True


def test_number_variants():
    schema = {"type": "number", "minimum": -10, "maximum": 10}
    assert benign_value(schema, variant="max") == 10
    assert benign_value(schema, variant="mid") == 0
    assert benign_value({"type": "integer", "minimum": 3}, variant="mid") == 3  # clamped into range


def test_integer_values_are_integers():
    assert isinstance(benign_value({"type": "integer", "minimum": 2.0}), int)


def test_array_builds_one_item_from_items():
    assert benign_value({"type": "array", "items": {"type": "integer"}}) == [1]
    assert benign_value({"type": "array", "items": {"type": "string"}, "minItems": 2}) == ["test", "test"]


def test_object_uses_required_properties_only():
    schema = {"type": "object", "properties": {"a": {"type": "string"}, "b": {"type": "integer"}}, "required": ["a"]}
    assert benign_value(schema) == {"a": "test"}


def test_nested_objects_recurse():
    schema = {"type": "object", "properties": {"inner": {"type": "object", "properties": {"city": {"type": "string"}}, "required": ["city"]}}, "required": ["inner"]}
    assert build_arguments(schema, include_optional=False) == {"inner": {"city": "London"}}


def test_anyof_picks_the_first_non_null_branch():
    assert benign_value({"anyOf": [{"type": "null"}, {"type": "string"}]}, "city") == "London"


def test_length_constraints_are_respected():
    assert benign_value({"type": "string", "minLength": 10}) == "testtestte"
    assert benign_value({"type": "string", "maxLength": 2}) == "te"


def test_unknown_schema_falls_back_to_test():
    assert benign_value({}) == "test"


def test_hostnames_only_use_the_invalid_tld():
    assert benign_value({"type": "string", "format": "uri"}).endswith(".invalid/test")
    assert benign_value({"type": "string", "format": "email"}).endswith("@example.invalid")


# ------------------------------------------------------------------ required vs optional


def test_required_only_then_all():
    schema = tool({"city": {"type": "string"}, "notes": {"type": "string"}}, ["city"])["inputSchema"]
    assert build_arguments(schema, include_optional=False) == {"city": "London"}
    assert build_arguments(schema, include_optional=True) == {"city": "London", "notes": "test"}


# ------------------------------------------------------------------ hostile payloads (BRD 8.5)


def test_hostile_kinds_and_order():
    kinds = [k for k, _ in hostile_payloads(NONCE)]
    assert kinds == ["path_traversal", "traversal_encoded", "shell_semicolon", "shell_substitution", "shell_backticks",
                     "shell_and", "sql", "oversized", "special_chars"]
    assert len(HOSTILE_KINDS) == 9


def test_hostile_payload_contents():
    p = dict(hostile_payloads(NONCE))
    assert p["path_traversal"] == "../../../../../../etc/passwd"
    assert p["traversal_encoded"] == "..%2f..%2f..%2f..%2fetc%2fpasswd"
    assert p["shell_semicolon"] == f"test; echo TPROBE-{NONCE}-$((6*7))"
    assert p["shell_substitution"] == f"$(echo TPROBE-{NONCE}-$((6*7)))"
    assert p["shell_backticks"] == f"`echo TPROBE-{NONCE}-$((6*7))`"
    assert p["shell_and"] == f"test && echo TPROBE-{NONCE}-$((6*7))"
    assert p["sql"] == "' OR '1'='1' --"
    assert p["oversized"] == "A" * 100_000
    assert "\x00" in p["special_chars"] and "\n" in p["special_chars"] and "\U0001f600" in p["special_chars"]


def test_the_proof_string_cannot_appear_from_echo_alone():
    """The payload contains $((6*7)) but the proof is TPROBE-<nonce>-42, which only a shell can produce."""
    for kind, value in hostile_payloads(NONCE):
        assert f"TPROBE-{NONCE}-42" not in value


# ------------------------------------------------------------------ the plan


def test_plan_starts_with_benign_calls():
    plan = plan_for_tool(tool({"city": {"type": "string"}, "notes": {"type": "string"}}, ["city"]), NONCE, max_calls=12)
    assert [p.label for p in plan[:2]] == ["benign", "benign-full"]
    assert plan[0].arguments == {"city": "London"}
    assert plan[1].arguments == {"city": "London", "notes": "test"}
    assert not plan[0].hostile


def test_hostile_inputs_change_one_parameter_and_keep_the_rest_benign():
    plan = plan_for_tool(tool({"city": {"type": "string"}, "notes": {"type": "string"}}, ["city"]), NONCE, max_calls=12)
    hostile = [p for p in plan if p.hostile]
    assert hostile
    for p in hostile:
        assert p.payload == p.arguments[p.param]
        other = "notes" if p.param == "city" else "city"
        assert p.arguments[other] in ("London", "test")


def test_kinds_are_spread_across_parameters_in_priority_order():
    plan = plan_for_tool(tool({"city": {"type": "string"}, "notes": {"type": "string"}}, ["city"]), NONCE, max_calls=12)
    hostile = [(p.kind, p.param) for p in plan if p.hostile]
    assert hostile[:4] == [("path_traversal", "city"), ("path_traversal", "notes"), ("traversal_encoded", "city"), ("traversal_encoded", "notes")]


def test_single_string_parameter_gets_all_nine_hostile_kinds():
    plan = plan_for_tool(tool({"host": {"type": "string"}}, ["host"]), NONCE, max_calls=12)
    assert [p.kind for p in plan if p.hostile] == [k for k, _ in HOSTILE_KINDS]
    assert len(plan) == 10  # one benign call plus nine hostile ones


def test_plan_never_exceeds_max_calls():
    assert len(plan_for_tool(tool({"host": {"type": "string"}}, ["host"]), NONCE, max_calls=5)) == 5
    assert len(plan_for_tool(tool({"a": {"type": "string"}, "b": {"type": "string"}, "c": {"type": "string"}}, ["a"]), NONCE, max_calls=12)) == 12


def test_enum_constrained_strings_are_not_attacked():
    plan = plan_for_tool(tool({"mode": {"type": "string", "enum": ["a", "b"]}}, ["mode"]), NONCE, max_calls=12)
    assert not any(p.hostile for p in plan)
    assert {p.arguments["mode"] for p in plan} == {"a", "b"}  # every enum value is tried


def test_numbers_get_boundary_calls_and_the_tool_is_called_at_least_four_times():
    add = tool({"a": {"type": "number", "minimum": -1e9, "maximum": 1e9}, "b": {"type": "number", "minimum": -1e9, "maximum": 1e9}}, ["a", "b"], "add")
    plan = plan_for_tool(add, NONCE, max_calls=12)
    assert [p.label for p in plan] == ["benign", "boundary-max", "boundary-mid", "repeat-1"]
    assert plan[1].arguments == {"a": 1e9, "b": 1e9}
    assert len(plan) >= MIN_CALLS_PER_TOOL


def test_a_tool_without_parameters_is_still_called_repeatedly():
    plan = plan_for_tool(tool({}), NONCE, max_calls=12)
    assert len(plan) == MIN_CALLS_PER_TOOL
    assert all(p.arguments == {} for p in plan)


def test_boolean_parameters_are_tried_both_ways():
    plan = plan_for_tool(tool({"flag": {"type": "boolean"}}, ["flag"]), NONCE, max_calls=12)
    assert {p.arguments["flag"] for p in plan} == {False, True}


def test_the_plan_is_deterministic():
    t = tool({"host": {"type": "string"}, "n": {"type": "integer", "minimum": 1, "maximum": 5}}, ["host"])
    assert plan_for_tool(t, NONCE, max_calls=12) == plan_for_tool(t, NONCE, max_calls=12)


def test_arguments_are_json_serializable():
    t = tool({"host": {"type": "string"}, "n": {"type": "integer"}, "flag": {"type": "boolean"}}, ["host"])
    for p in plan_for_tool(t, NONCE, max_calls=12):
        json.dumps(p.arguments)


def test_missing_input_schema_does_not_crash():
    assert len(plan_for_tool({"name": "bare"}, NONCE, max_calls=12)) == MIN_CALLS_PER_TOOL


# ------------------------------------------------------------------ resource templates


def test_expand_template():
    assert expand_template("file:///workspace/{name}") == "file:///workspace/sample.txt"
    assert expand_template("x://{+path}/{id}") == "x://sample.txt/sample.txt"
    assert expand_template("calc://help") == "calc://help"
