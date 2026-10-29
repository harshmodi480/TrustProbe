from pathlib import Path

import pytest

from trustprobe.config import ConfigError, load_config, new_nonce, parse_config, save_run_state

ROOT = Path(__file__).resolve().parent.parent


def base(tmp_path: Path) -> dict:
    (tmp_path / "srv").mkdir(exist_ok=True)
    return {
        "name": "t",
        "server": {"source": {"type": "path", "path": "srv"}, "command": ["python", "server.py"]},
    }


def test_example_config_loads():
    cfg = load_config(ROOT / "examples" / "scan.benign_calc.yaml")
    assert cfg.name == "Benign calculator demo"
    assert cfg.runtime == "python"
    assert cfg.source_path == (ROOT / "demo_servers" / "benign_calc").resolve()
    assert cfg.out_path == (ROOT / "out" / "benign_calc").resolve()


def test_defaults(tmp_path):
    cfg = parse_config(base(tmp_path), tmp_path)
    assert cfg.scan.mode == "full"
    assert cfg.scan.dynamic.max_calls_per_tool == 12
    assert cfg.scan.dynamic.rugpull_delay_s == 10
    assert cfg.policy.do_not_use_on[0].value == "critical"


def test_command_must_be_a_list(tmp_path):
    d = base(tmp_path)
    d["server"]["command"] = "python server.py"
    with pytest.raises(ConfigError, match="server.command.*list of strings"):
        parse_config(d, tmp_path)


def test_unknown_field_is_named(tmp_path):
    d = base(tmp_path)
    d["scan"] = {"mdoe": "full"}
    with pytest.raises(ConfigError, match="scan.mdoe"):
        parse_config(d, tmp_path)


def test_bad_enum_value_is_named(tmp_path):
    d = base(tmp_path)
    d["scan"] = {"mode": "turbo"}
    with pytest.raises(ConfigError, match="scan.mode"):
        parse_config(d, tmp_path)


def test_missing_path_is_reported(tmp_path):
    d = base(tmp_path)
    d["server"]["source"]["path"] = "nope"
    with pytest.raises(ConfigError, match="server.source.path.*does not exist"):
        parse_config(d, tmp_path)


def test_path_source_needs_path(tmp_path):
    d = base(tmp_path)
    d["server"]["source"] = {"type": "path"}
    with pytest.raises(ConfigError, match="source.path is required"):
        parse_config(d, tmp_path)


def test_package_source_needs_package(tmp_path):
    d = base(tmp_path)
    d["server"]["source"] = {"type": "npm"}
    with pytest.raises(ConfigError, match="source.package is required"):
        parse_config(d, tmp_path)


def test_unknown_capability(tmp_path):
    d = base(tmp_path)
    d["server"]["declared_capabilities"] = ["teleport"]
    with pytest.raises(ConfigError, match="declared_capabilities"):
        parse_config(d, tmp_path)


def test_llm_review_requires_llm(tmp_path):
    d = base(tmp_path)
    d["scan"] = {"static": {"llm_review": True}}
    with pytest.raises(ConfigError, match="llm.enabled"):
        parse_config(d, tmp_path)


def test_runtime_autodetect(tmp_path):
    d = base(tmp_path)
    assert parse_config(d, tmp_path).runtime == "python"
    (tmp_path / "srv" / "package.json").write_text("{}")
    assert parse_config(d, tmp_path).runtime == "node"


def test_missing_config_file(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "missing.yaml")


def test_nonce_and_run_state(tmp_path):
    n = new_nonce()
    assert len(n) == 8 and int(n, 16) >= 0
    p = save_run_state(tmp_path / "out", n)
    assert n in p.read_text()
