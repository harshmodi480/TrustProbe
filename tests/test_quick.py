"""`trustprobe quick`: default config generation. No Docker."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from trustprobe.cli import app
from trustprobe.config import parse_config
from trustprobe.quick import QuickError, build_quick_config, parse_package

ROOT = Path(__file__).resolve().parent.parent


def cfg_of(target, **kw):
    return parse_config(build_quick_config(target, **kw), Path.cwd())


# ------------------------------------------------------------------ package specs


@pytest.mark.parametrize("spec,expected", [
    ("npm:some-server", ("npm", "some-server", None)),
    ("npm:some-server@1.2.3", ("npm", "some-server", "1.2.3")),
    ("npm:@scope/some-server", ("npm", "@scope/some-server", None)),
    ("npm:@scope/some-server@0.4.0", ("npm", "@scope/some-server", "0.4.0")),
    ("pypi:some-server", ("pypi", "some-server", None)),
    ("pypi:some-server==1.2.3", ("pypi", "some-server", "1.2.3")),
])
def test_parse_package(spec, expected):
    assert parse_package(spec) == expected


@pytest.mark.parametrize("spec", ["pypi:", "npm:", "pypi:some-server>=1.0", "pypi:bad name", "npm:Bad Name", "gem:x"])
def test_bad_package_specs_are_rejected_with_a_fix(spec):
    with pytest.raises(QuickError):
        parse_package(spec)


def test_npm_package_config():
    cfg = cfg_of("npm:@scope/server@1.0.0")
    assert (cfg.server.source.type, cfg.server.source.package, cfg.server.source.version) == ("npm", "@scope/server", "1.0.0")
    assert cfg.runtime == "node" and cfg.server.command == ["npx", "--no-install", "@scope/server"]


def test_pypi_package_config():
    cfg = cfg_of("pypi:mcp-server-time==1.2.3")
    assert cfg.runtime == "python" and cfg.server.command == ["mcp-server-time"] and cfg.server.source.version == "1.2.3"


def test_an_unpinned_package_is_allowed_but_stays_visible():
    cfg = cfg_of("pypi:mcp-server-time")
    assert cfg.server.source.version is None  # MD-002 will flag it in the report


def test_command_override():
    assert cfg_of("pypi:x", command=["python", "-m", "x"]).server.command == ["python", "-m", "x"]


def test_output_goes_to_a_per_server_folder():
    assert build_quick_config("npm:@scope/server")["out_dir"] == "out/quick-server/"


# ------------------------------------------------------------------ directories


def test_python_directory_with_requirements(tmp_path):
    (tmp_path / "server.py").write_text("print()")
    (tmp_path / "requirements.txt").write_text("mcp==1.30.0\n")
    cfg = cfg_of(str(tmp_path))
    assert cfg.runtime == "python" and cfg.server.command == ["python", "server.py"]
    assert cfg.server.install.requirements == "requirements.txt"
    assert cfg.source_path == tmp_path.resolve()


@pytest.mark.parametrize("entry", ["main.py", "app.py", "__main__.py"])
def test_other_python_entry_points(tmp_path, entry):
    (tmp_path / entry).write_text("print()")
    assert cfg_of(str(tmp_path)).server.command == ["python", entry]


def test_server_py_wins_over_main_py(tmp_path):
    (tmp_path / "main.py").write_text("")
    (tmp_path / "server.py").write_text("")
    assert cfg_of(str(tmp_path)).server.command == ["python", "server.py"]


def test_python_directory_without_requirements_installs_nothing(tmp_path):
    (tmp_path / "server.py").write_text("")
    assert cfg_of(str(tmp_path)).server.install.requirements is None


def test_node_directory_uses_bin_then_main(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"name": "x", "bin": {"x": "dist/cli.js"}, "main": "dist/index.js"}))
    cfg = cfg_of(str(tmp_path))
    assert cfg.runtime == "node" and cfg.server.command == ["node", "dist/cli.js"] and cfg.server.install.package_json


def test_node_directory_with_a_string_bin_or_main(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"bin": "cli.js"}))
    assert cfg_of(str(tmp_path)).server.command == ["node", "cli.js"]
    (tmp_path / "package.json").write_text(json.dumps({"main": "lib/main.js"}))
    assert cfg_of(str(tmp_path)).server.command == ["node", "lib/main.js"]


def test_node_directory_falls_back_to_index_js(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    (tmp_path / "index.js").write_text("")
    assert cfg_of(str(tmp_path)).server.command == ["node", "index.js"]


def test_a_directory_with_no_entry_point_explains_what_to_do(tmp_path):
    with pytest.raises(QuickError, match="no server entry point found.*scan.yaml"):
        build_quick_config(str(tmp_path))


def test_node_directory_without_an_entry_point(tmp_path):
    (tmp_path / "package.json").write_text("{}")
    with pytest.raises(QuickError, match="no entry point"):
        build_quick_config(str(tmp_path))


def test_a_broken_package_json_is_reported(tmp_path):
    (tmp_path / "package.json").write_text("{not json")
    with pytest.raises(QuickError, match="package.json could not be read"):
        build_quick_config(str(tmp_path))


def test_missing_path_and_file_targets(tmp_path):
    with pytest.raises(QuickError, match="does not exist"):
        build_quick_config(str(tmp_path / "nope"))
    f = tmp_path / "server.py"
    f.write_text("")
    with pytest.raises(QuickError, match="is a file"):
        build_quick_config(str(f))


def test_command_override_skips_entry_point_detection(tmp_path):
    cfg = cfg_of(str(tmp_path), command=["python", "-m", "mypkg"])
    assert cfg.server.command == ["python", "-m", "mypkg"]


def test_relative_directories_resolve_against_the_base(tmp_path):
    (tmp_path / "srv").mkdir()
    (tmp_path / "srv" / "server.py").write_text("")
    assert cfg_of("srv", base=tmp_path).source_path == (tmp_path / "srv").resolve()


def test_the_node_demo_server_is_detected_as_node():
    cfg = cfg_of(str(ROOT / "demo_servers" / "node_echo"))
    assert cfg.runtime == "node" and cfg.server.command == ["node", "server.js"] and cfg.server.install.package_json


def test_the_demo_server_is_detected_exactly_like_its_example_config():
    quick = cfg_of(str(ROOT / "demo_servers" / "benign_calc"))
    example = parse_config(build_quick_config(str(ROOT / "demo_servers" / "benign_calc")), Path.cwd())
    assert quick.server.command == ["python", "server.py"] and quick.server.install.requirements == "requirements.txt"
    assert example.source_path == (ROOT / "demo_servers" / "benign_calc").resolve()


# ------------------------------------------------------------------ the command


def test_quick_command_reports_bad_targets_as_scanner_errors():
    res = CliRunner().invoke(app, ["quick", "no-such-directory-here"])
    assert res.exit_code == 3 and "does not exist" in res.output


def test_quick_command_reports_bad_package_specs():
    res = CliRunner().invoke(app, ["quick", "pypi:some-server>=1.0"])
    assert res.exit_code == 3 and "==" in res.output


def test_quick_rejects_a_bad_fail_on_value():
    res = CliRunner().invoke(app, ["quick", str(ROOT / "demo_servers" / "benign_calc"), "--fail-on", "never", "--yes"])
    assert res.exit_code == 3
