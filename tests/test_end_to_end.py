"""End-to-end scans of the four demo servers inside the real sandbox. Needs Docker."""

import json
import os
import re
import subprocess
import sys
import uuid
from pathlib import Path

import pytest
import yaml

from trustprobe.models import Confidence
from trustprobe.report.render import DISCLAIMER
from trustprobe.sandbox.docker import run_docker
from trustprobe.scoring import severity_rank
from trustprobe.models import Severity

pytestmark = pytest.mark.docker

ROOT = Path(__file__).resolve().parent.parent
SERVERS = ["benign_calc", "malicious_weather", "rugpull_math", "injectable_diag"]
EXPECTED = yaml.safe_load((ROOT / "tests" / "expected_findings.yaml").read_text(encoding="utf-8"))
EXIT_CODES = {"no_issues_found": 0, "do_not_use": 2}
CANARY = f"canary-{uuid.uuid4().hex}"


def trustprobe(*args: str, env_extra: dict | None = None, timeout: int = 400) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, **(env_extra or {})}
    return subprocess.run([sys.executable, "-m", "trustprobe", *args], capture_output=True, text=True, cwd=ROOT,
                          env=env, timeout=timeout, encoding="utf-8", errors="replace")


@pytest.fixture(scope="module")
def scans(tmp_path_factory):
    """Run every demo server once (full scan) with a canary in the host environment."""
    runs = {}
    for name in SERVERS:
        out = tmp_path_factory.mktemp(f"scan_{name}")
        proc = trustprobe("scan", "-c", str(ROOT / "examples" / f"scan.{name}.yaml"), "--yes", "--out", str(out),
                          env_extra={"TP_HOST_CANARY": CANARY})
        results = json.loads((out / "results.json").read_text(encoding="utf-8")) if (out / "results.json").exists() else None
        runs[name] = {"proc": proc, "out": out, "results": results}
    return runs


def ids(results) -> set[str]:
    return {f["rule_id"] for f in results["findings"]}


def need_monitor(results):
    if results["coverage"]["dynamic_probes_skipped"]:
        pytest.skip("strace is unavailable in this Docker setup, so the syscall probes did not run")


# ------------------------------------------------------------------ verdicts and expected findings


@pytest.mark.parametrize("name", SERVERS)
def test_scan_completes_with_the_expected_verdict_and_exit_code(scans, name):
    run = scans[name]
    assert run["results"] is not None, run["proc"].stdout + run["proc"].stderr
    need_monitor(run["results"])
    expected = EXPECTED[name]["verdict"]
    assert run["results"]["verdict"] == expected
    assert run["proc"].returncode == EXIT_CODES[expected], run["proc"].stdout


@pytest.mark.parametrize("name", SERVERS)
def test_the_expected_rule_ids_appear(scans, name):
    results = scans[name]["results"]
    need_monitor(results)
    missing = set(EXPECTED[name]["full"]) - ids(results)
    assert not missing, f"{name} is missing {sorted(missing)}; found {sorted(ids(results))}"


def test_benign_calc_has_nothing_above_info(scans):
    results = scans["benign_calc"]["results"]
    worst = [f["id"] for f in results["findings"] if severity_rank(Severity(f["severity"])) > severity_rank(Severity.info)]
    assert worst == []
    assert results["verdict"] == "no_issues_found" and results["trust_score"] == 100


def test_malicious_weather_evidence(scans):
    results = scans["malicious_weather"]["results"]
    need_monitor(results)
    by_id = {f["id"]: f for f in results["findings"]}
    dy1 = by_id["DY-001:get_weather"]
    assert dy1["severity"] == "critical" and dy1["confidence"] == "confirmed"
    assert any(e["matched"] and e["matched"].startswith("HONEY-") and e["matched"] in e["detail"] for e in dy1["evidence"])
    assert any(e["kind"] == "syscall" and "id_rsa" in e["detail"] for e in dy1["evidence"])  # the file read behind the leak
    dy3 = by_id["DY-003:get_weather"]
    assert any(e["matched"] == "203.0.113.10" and "203.0.113.10" in e["detail"] and "443" in e["summary"] for e in dy3["evidence"])
    assert {"TP-001:get_weather", "TP-005:get_weather", "RS-001:readme", "DY-005:get_weather"} <= set(by_id)


def test_rug_pull_is_caught_without_a_list_changed_notification(scans):
    results = scans["rugpull_math"]["results"]
    dy4 = next(f for f in results["findings"] if f["rule_id"] == "DY-004")
    assert dy4["severity"] == "critical" and dy4["confidence"] == "confirmed"
    diff = next(e for e in dy4["evidence"] if e["kind"] == "diff")
    assert "Add two numbers." in diff["detail"] and "<IMPORTANT>" in diff["detail"] and "sidenote" in diff["detail"]
    assert "no tools/list_changed notification" in dy4["description"]
    # the swap needs 3 calls before the second listing; the default plan makes them
    assert results["coverage"]["calls_made"] >= 3
    assert results["coverage"]["snapshots"] == ["initial", "after_probes", "after_delay"]
    # the static rules re-run on the changed definition
    by_id = {f["id"]: f for f in results["findings"]}
    assert {"TP-001:add", "TP-005:add"} <= set(by_id)
    assert all("[snapshot after_probes]" in e["summary"] for e in by_id["TP-001:add"]["evidence"])


def test_shell_injection_is_proven_and_dy007_is_merged(scans):
    results = scans["injectable_diag"]["results"]
    need_monitor(results)
    by_id = {f["id"]: f for f in results["findings"]}
    shell = by_id["DY-006:run_diagnostic"]
    assert shell["severity"] == "critical" and shell["confidence"] == "confirmed"
    nonce = results["meta"]["nonce"]
    assert any(e["matched"] == f"TPROBE-{nonce}-42" and e["matched"] in e["detail"] for e in shell["evidence"])
    assert any("DY-007, merged" in e["summary"] for e in shell["evidence"])
    assert "DY-007:run_diagnostic" not in by_id  # folded into the shell finding, not reported twice
    traversal = by_id["DY-006:read_note"]
    assert any(e["matched"] == "root:x:0:0:" for e in traversal["evidence"])
    assert by_id["DY-010:read_note"]["severity"] == "low"


# ------------------------------------------------------------------ evidence and honesty


@pytest.mark.parametrize("name", SERVERS)
def test_every_confirmed_finding_carries_its_proof(scans, name):
    for f in scans[name]["results"]["findings"]:
        if f["confidence"] != Confidence.confirmed.value:
            continue
        assert f["evidence"], f["id"]
        proof = [e for e in f["evidence"] if e["kind"] == "diff" or (e.get("matched") and e["matched"] in e["detail"])]
        assert proof, f"{f['id']} has no evidence that contains its proof"


@pytest.mark.parametrize("name", SERVERS)
def test_coverage_and_disclaimer_are_always_reported(scans, name):
    run = scans[name]
    cov = run["results"]["coverage"]
    assert cov["mode"] == "full" and cov["not_covered"] and cov["tools_called"] == cov["tools_total"]
    html = (run["out"] / "report.html").read_text(encoding="utf-8")
    assert DISCLAIMER in html and "Coverage" in html and "Never covered by this scan" in html
    assert run["results"]["verdict"] != "safe"
    assert "safe" not in run["results"]["meta"]["verdict_reason"].replace("not a claim that the server is safe", "")


@pytest.mark.parametrize("name", SERVERS)
def test_report_opens_from_disk_with_a_verdict_banner(scans, name):
    html = (scans[name]["out"] / "report.html").read_text(encoding="utf-8")
    assert re.search(r'class="banner (bad|warn|good)"', html)
    assert "<title>TrustProbe report:" in html
    assert not re.search(r"""(?:src|href)=["']https?://""", html)


@pytest.mark.parametrize("name", SERVERS)
def test_a_small_server_scans_in_under_three_minutes(scans, name):
    assert scans[name]["results"]["meta"]["duration_s"] < 180


# ------------------------------------------------------------------ the host stays out of the output


def test_no_host_paths_usernames_or_environment_values_in_out(scans):
    import getpass

    needles = {CANARY, getpass.getuser(), str(Path.home()), str(Path.home()).replace("\\", "/"), str(ROOT), str(ROOT).replace("\\", "/")}
    needles = {n for n in needles if len(n) >= 3}
    leaks = []
    for run in scans.values():
        for path in run["out"].rglob("*"):
            if path.is_file():
                text = path.read_text(encoding="utf-8", errors="replace").lower()
                leaks += [f"{path.name}: {n}" for n in needles if n.lower() in text]
    assert leaks == []


def test_the_scanner_cleans_up_after_itself(scans):
    assert run_docker(["ps", "-a", "--filter", "name=tp-", "--format", "{{.Names}}"]).stdout.strip() == ""
    assert run_docker(["volume", "ls", "--filter", "name=tp-audit-", "--format", "{{.Name}}"]).stdout.strip() == ""


# ------------------------------------------------------------------ other modes


def test_static_only_scan_makes_no_tool_calls_and_cannot_be_clean(tmp_path):
    proc = trustprobe("scan", "-c", str(ROOT / "examples" / "scan.benign_calc.yaml"), "--static-only", "--yes", "--out", str(tmp_path))
    results = json.loads((tmp_path / "results.json").read_text(encoding="utf-8"))
    assert results["coverage"]["mode"] == "static" and results["coverage"]["calls_made"] == 0
    assert results["coverage"]["dynamic"] == "skipped: static-only mode"
    assert results["verdict"] == "use_with_caution" and "dynamic analysis not run" in results["meta"]["verdict_reason"]
    assert proc.returncode == 0


def test_fail_on_caution_with_a_clean_server_still_exits_zero(tmp_path):
    proc = trustprobe("scan", "-c", str(ROOT / "examples" / "scan.benign_calc.yaml"), "--yes", "--out", str(tmp_path), "--fail-on", "caution")
    assert proc.returncode == 0, proc.stdout


def test_quick_scans_a_local_directory_without_a_config(tmp_path):
    proc = trustprobe("quick", str(ROOT / "demo_servers" / "benign_calc"), "--yes", "--out", str(tmp_path))
    results = json.loads((tmp_path / "results.json").read_text(encoding="utf-8"))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "Generated config" in proc.stdout and "python server.py" in proc.stdout
    assert results["verdict"] == "no_issues_found" and results["coverage"]["mode"] == "full"
    assert results["coverage"]["tools_called"] == 3
    assert (tmp_path / "report.html").is_file()


def test_quick_finds_the_same_problems_as_the_example_config(tmp_path):
    proc = trustprobe("quick", str(ROOT / "demo_servers" / "malicious_weather"), "--yes", "--out", str(tmp_path))
    results = json.loads((tmp_path / "results.json").read_text(encoding="utf-8"))
    need_monitor(results)
    assert proc.returncode == 2 and results["verdict"] == "do_not_use"
    assert {"DY-001", "DY-002", "DY-003", "TP-001"} <= {f["rule_id"] for f in results["findings"]}


def test_node_servers_run_in_the_node_sandbox_image(tmp_path):
    proc = trustprobe("quick", str(ROOT / "demo_servers" / "node_echo"), "--yes", "--out", str(tmp_path))
    results = json.loads((tmp_path / "results.json").read_text(encoding="utf-8"))
    need_monitor(results)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "runtime node" in proc.stdout and "node server.js" in proc.stdout
    assert results["verdict"] == "no_issues_found" and results["meta"]["server_name"] == "node-echo"
    assert results["coverage"]["tools_called"] == 1 and results["coverage"]["calls_made"] >= 4
    assert results["coverage"]["hostile_inputs_sent"] >= 1 and results["coverage"]["syscall_events"] > 0
    assert results["coverage"]["dynamic"] == "ran"


def test_the_llm_checks_are_off_by_default_and_never_block_a_scan(scans):
    for name in SERVERS:
        llm = scans[name]["results"]["coverage"]["llm"]
        assert llm["enabled"] is False and llm["active"] is False and llm["calls"] == 0
        assert "explanations" not in scans[name]["results"]["meta"]


def test_declining_the_confirmation_runs_nothing(tmp_path):
    proc = subprocess.run([sys.executable, "-m", "trustprobe", "scan", "-c", str(ROOT / "examples" / "scan.benign_calc.yaml"), "--out", str(tmp_path)],
                          input="n\n", capture_output=True, text=True, cwd=ROOT, timeout=120)
    assert proc.returncode == 3 and "aborted" in proc.stderr
    assert not (tmp_path / "results.json").exists()
    assert run_docker(["ps", "-a", "--filter", "name=tp-", "--format", "{{.Names}}"]).stdout.strip() == ""
