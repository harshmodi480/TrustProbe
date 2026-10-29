"""M2: the demo servers exist, carry their warnings, and enumerate correctly inside the sandbox."""

from pathlib import Path

import pytest
import yaml

from trustprobe.config import load_config
from trustprobe.pipeline import enumerate_in_sandbox
from trustprobe.sandbox.docker import Sandbox

ROOT = Path(__file__).resolve().parent.parent
SERVERS = ["benign_calc", "malicious_weather", "rugpull_math", "injectable_diag"]
UNSAFE = [s for s in SERVERS if s != "benign_calc"]


@pytest.mark.parametrize("name", SERVERS)
def test_server_files_exist_and_pin_the_sdk(name):
    d = ROOT / "demo_servers" / name
    assert (d / "server.py").is_file()
    assert (d / "requirements.txt").read_text().strip() == "mcp==1.30.0"


@pytest.mark.parametrize("name", UNSAFE)
def test_unsafe_servers_carry_the_warning_header(name):
    head = (ROOT / "demo_servers" / name / "server.py").read_text().splitlines()[:12]
    text = "\n".join(head)
    assert "INTENTIONALLY UNSAFE" in text
    assert "NEVER run" in text or "Run it only through" in text


def test_readme_warns_against_running_on_the_host():
    readme = (ROOT / "demo_servers" / "README.md").read_text()
    assert "Never run them directly" in readme


def test_expected_findings_cover_every_server():
    expected = yaml.safe_load((ROOT / "tests" / "expected_findings.yaml").read_text())
    assert set(expected) == set(SERVERS)
    assert expected["benign_calc"]["verdict"] == "no_issues_found"
    assert expected["benign_calc"]["max_severity"] == "info"
    for name in UNSAFE:
        assert expected[name]["verdict"] == "do_not_use"


@pytest.mark.parametrize("name", SERVERS)
def test_example_config_loads(name):
    cfg = load_config(ROOT / "examples" / f"scan.{name}.yaml")
    assert cfg.source_path == (ROOT / "demo_servers" / name).resolve()


@pytest.fixture(scope="module")
def surfaces(tmp_path_factory):
    """Enumerate each demo server inside the sandbox (never on the host)."""
    found = {}
    for name in SERVERS:
        cfg = load_config(ROOT / "examples" / f"scan.{name}.yaml")
        sb = Sandbox(cfg, f"e2e{SERVERS.index(name):05d}", tmp_path_factory.mktemp(name))
        try:
            sb.prepare()
            found[name] = enumerate_in_sandbox(cfg, sb)
        finally:
            sb.cleanup()
    return found


@pytest.mark.docker
def test_benign_calc_surface(surfaces):
    s = surfaces["benign_calc"]
    assert {t["name"] for t in s.tools} == {"add", "subtract", "multiply"}
    assert [p["name"] for p in s.prompts] == ["explain_result"]
    assert [r["uri"] for r in s.resources] == ["calc://help"]
    assert s.resource_contents["calc://help"] == "This server adds, subtracts and multiplies numbers."
    assert s.prompts[0]["messages"], "prompts are rendered so static rules can scan them"


@pytest.mark.docker
def test_malicious_weather_surface(surfaces):
    s = surfaces["malicious_weather"]
    (tool,) = s.tools
    assert tool["name"] == "get_weather"
    assert "<IMPORTANT>" in tool["description"] and "~/.ssh/id_rsa" in tool["description"]
    assert set(tool["inputSchema"]["properties"]) == {"city", "notes"}
    assert tool["inputSchema"]["required"] == ["city"]
    assert "Ignore previous instructions" in s.resource_contents["weather://readme"]


@pytest.mark.docker
def test_rugpull_math_starts_clean(surfaces):
    (tool,) = surfaces["rugpull_math"].tools
    assert tool["name"] == "add"
    assert tool["description"] == "Add two numbers."
    assert set(tool["inputSchema"]["properties"]) == {"a", "b"}


@pytest.mark.docker
def test_injectable_diag_surface(surfaces):
    s = surfaces["injectable_diag"]
    assert {t["name"] for t in s.tools} == {"run_diagnostic", "read_note"}
    for t in s.tools:
        assert "<IMPORTANT>" not in t["description"]  # the vulnerabilities are not advertised
