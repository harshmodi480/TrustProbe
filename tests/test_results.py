"""Result assembly: coverage block, verdict inputs, capabilities, metadata. No Docker."""

import json
import time
from pathlib import Path

from trustprobe import __version__
from trustprobe.config import parse_config
from trustprobe.dynamic.inputs import TestInput
from trustprobe.dynamic.runner import DynamicAnalysis, SessionData
from trustprobe.mcp_client import CallRecord, make_snapshot
from trustprobe.models import Category, Confidence, Evidence, Finding, ServerSurface, Severity
from trustprobe.pipeline import NOT_COVERED, build_result, static_analysis
from trustprobe.static.analyzer import AnalysisResult

ROOT = Path(__file__).resolve().parent.parent
TOOL = {"name": "add", "description": "Add two numbers.", "inputSchema": {"type": "object", "properties": {"a": {"type": "number"}}, "required": ["a"]}}


def cfg(tmp_path, **policy):
    (tmp_path / "srv").mkdir(exist_ok=True)
    data = {"name": "Demo", "server": {"source": {"type": "path", "path": "srv"}, "command": ["python", "server.py"]}}
    if policy:
        data["policy"] = policy
    return parse_config(data, tmp_path)


def surface():
    return ServerSurface(server_name="demo-server", server_version="1.2.3", tools=[TOOL],
                         prompts=[{"name": "p", "description": "A prompt."}],
                         resources=[{"uri": "x://r", "name": "r", "description": "A resource."}],
                         resource_templates=[], resource_contents={"x://r": "text"})


def finding(rule="DY-001", target="add", severity=Severity.critical, confidence=Confidence.confirmed, phase="dynamic"):
    return Finding(id=f"{rule}:{target}", rule_id=rule, title="t", category=Category.data_exfiltration, severity=severity,
                   confidence=confidence, target=target, phase=phase, description="d", impact="i", remediation="r",
                   evidence=[Evidence(kind="text", summary="s", detail="d")])


def session(finished=True):
    now = time.time()
    data = SessionData(started=now - 5, ended=now, finished=finished, probed=True)
    data.surface = surface()
    data.snapshots = [make_snapshot("initial", [TOOL]), make_snapshot("after_probes", [TOOL]), make_snapshot("after_delay", [TOOL])]
    data.calls = [CallRecord("tool", "add", {"a": 1}, now, now + 0.1, text="2"),
                  CallRecord("tool", "add", {"a": 2}, now, now + 0.1, text="3"),
                  CallRecord("prompt", "p", {}, now, now + 0.1), CallRecord("resource", "x://r", None, now, now + 0.1)]
    data.inputs = {0: TestInput("benign", {"a": 1}), 1: TestInput("hostile:sql", {"a": 2}, True, "sql", "a")}
    return data


def clean_dyn():
    return DynamicAnalysis(probes_run=["DY-001", "DY-002", "DY-003", "DY-004"], syscall_events=900)


def build(tmp_path, *, static=None, dyn=None, data="default", mode="full", **kw):
    c = cfg(tmp_path)
    s = surface()
    static = static if static is not None else static_analysis(c, s)
    data = session() if data == "default" else data
    return build_result(c, "7f3a91c2", s, static, mode=mode, data=data, dyn=dyn, started=time.time() - 5, **kw)


# ------------------------------------------------------------------ verdicts


def test_clean_complete_full_scan_is_no_issues_found(tmp_path):
    r = build(tmp_path, dyn=clean_dyn())
    assert (r.verdict, r.trust_score) == ("no_issues_found", 100)
    assert r.coverage["dynamic"] == "ran"


def test_confirmed_critical_is_do_not_use(tmp_path):
    r = build(tmp_path, dyn=DynamicAnalysis(findings=[finding()], probes_run=["DY-001"]))
    assert r.verdict == "do_not_use" and "confirmed critical" in r.meta["verdict_reason"]


def test_the_policy_decides_which_severities_block(tmp_path):
    high = finding("DY-002", severity=Severity.high)
    dyn = DynamicAnalysis(findings=[high], probes_run=["DY-002"])
    assert build(tmp_path, dyn=dyn).verdict == "use_with_caution"
    c = cfg(tmp_path, do_not_use_on=["high", "critical"])
    r = build_result(c, "n", surface(), static_analysis(c, surface()), mode="full", data=session(), dyn=dyn, started=time.time())
    assert r.verdict == "do_not_use"


def test_static_mode_never_says_no_issues_found(tmp_path):
    r = build(tmp_path, mode="static", data=None, server_run=False)
    assert r.verdict == "use_with_caution"
    assert r.coverage["mode"] == "static"
    assert r.coverage["dynamic"] == "skipped: saved surface supplied (the server was not run)"
    assert "dynamic analysis not run" in r.meta["verdict_reason"]
    assert r.coverage["dynamic_probes_run"] == [] and r.coverage["calls_made"] == 0


def test_static_only_run_in_the_sandbox_has_its_own_note(tmp_path):
    assert build(tmp_path, mode="static", data=None).coverage["dynamic"] == "skipped: static-only mode"


def test_skipped_probes_cap_the_verdict_and_are_listed(tmp_path):
    dyn = DynamicAnalysis(probes_run=["DY-001"], probes_skipped={"DY-002": "strace unavailable in sandbox"})
    r = build(tmp_path, dyn=dyn)
    assert r.verdict == "use_with_caution"
    assert r.coverage["dynamic_probes_skipped"] == {"DY-002": "strace unavailable in sandbox"}
    assert r.coverage["dynamic"].startswith("partial:") and "DY-002" in r.coverage["dynamic"]


def test_a_failed_probe_caps_the_verdict(tmp_path):
    r = build(tmp_path, dyn=DynamicAnalysis(probes_run=["DY-001"], probe_errors={"DY-004": "RuntimeError: boom"}))
    assert r.verdict == "use_with_caution" and r.coverage["dynamic_probe_errors"] == {"DY-004": "RuntimeError: boom"}


def test_an_unfinished_session_caps_the_verdict(tmp_path):
    assert build(tmp_path, dyn=clean_dyn(), data=session(finished=False)).verdict == "use_with_caution"


def test_a_time_limit_caps_the_verdict(tmp_path):
    assert build(tmp_path, dyn=clean_dyn(), timed_out=True).verdict == "use_with_caution"


def test_a_failed_static_rule_caps_the_verdict(tmp_path):
    static = AnalysisResult(rules_run=["TP-001"], rule_errors={"PM-003": "RuntimeError: x"})
    r = build(tmp_path, static=static, dyn=clean_dyn())
    assert r.verdict == "use_with_caution" and r.coverage["static_rule_errors"] == {"PM-003": "RuntimeError: x"}


def test_a_confirmed_critical_still_wins_over_an_incomplete_scan(tmp_path):
    dyn = DynamicAnalysis(findings=[finding()], probes_skipped={"DY-002": "strace unavailable in sandbox"})
    assert build(tmp_path, dyn=dyn).verdict == "do_not_use"


# ------------------------------------------------------------------ coverage block (BRD 10.3)


def test_coverage_has_every_documented_key(tmp_path):
    cov = build(tmp_path, dyn=clean_dyn(), monitor_note="ran with SYS_PTRACE").coverage
    assert {"mode", "static_rules_run", "dynamic_probes_run", "dynamic_probes_skipped", "tools_total", "tools_called",
            "prompts_total", "prompts_fetched", "resources_total", "resources_read", "calls_made", "hostile_inputs_sent",
            "monitor_note", "not_covered"} <= set(cov)
    assert cov["monitor_note"] == "ran with SYS_PTRACE"


def test_coverage_counts(tmp_path):
    cov = build(tmp_path, dyn=clean_dyn()).coverage
    assert (cov["tools_total"], cov["tools_called"]) == (1, 1)
    assert (cov["prompts_total"], cov["prompts_fetched"]) == (1, 1)
    assert (cov["resources_total"], cov["resources_read"]) == (1, 1)
    assert (cov["calls_made"], cov["hostile_inputs_sent"]) == (2, 1)
    assert cov["snapshots"] == ["initial", "after_probes", "after_delay"]
    assert cov["syscall_events"] == 900


def test_not_covered_is_always_present_and_honest(tmp_path):
    assert build(tmp_path, dyn=clean_dyn()).coverage["not_covered"] == NOT_COVERED
    assert build(tmp_path, mode="static", data=None).coverage["not_covered"] == NOT_COVERED
    assert any("Servers that detect the sandbox" in n for n in NOT_COVERED)


def test_static_rules_run_are_listed(tmp_path):
    rules = build(tmp_path, dyn=clean_dyn()).coverage["static_rules_run"]
    assert "TP-001" in rules and "MD-002" in rules and rules == sorted(rules)


# ------------------------------------------------------------------ capabilities, meta, serialization


def test_capabilities_merge_inferred_and_observed(tmp_path):
    static = AnalysisResult(capabilities=["filesystem"], rules_run=["PM-002"])
    r = build(tmp_path, static=static, dyn=DynamicAnalysis(observed_capabilities=["network"], probes_run=["DY-003"]))
    assert r.capabilities == ["filesystem", "network"]
    assert r.coverage["capabilities_inferred"] == ["filesystem"] and r.coverage["capabilities_observed"] == ["network"]


def test_meta(tmp_path):
    m = build(tmp_path, dyn=clean_dyn()).meta
    assert m["target"] == "Demo" and m["nonce"] == "7f3a91c2" and m["scanner_version"] == __version__
    assert (m["server_name"], m["server_version"]) == ("demo-server", "1.2.3")
    assert m["mode"] == "full" and m["tool_calls_made"] == 2 and m["duration_s"] >= 0
    assert m["source"] == "path:srv" and "Users" not in m["source"]
    assert m["inventory"]["tools"][0]["name"] == "add"
    assert m["inventory"]["resources"][0]["uri"] == "x://r"
    assert m["verdict_reason"]


def test_snapshot_findings_are_included(tmp_path):
    extra = finding("TP-001", severity=Severity.high, confidence=Confidence.pattern_match, phase="static")
    r = build_result(cfg(tmp_path), "n", surface(), static_analysis(cfg(tmp_path), surface()), mode="full", data=session(),
                     dyn=clean_dyn(), snapshot_findings=[extra], started=time.time())
    assert "TP-001:add" in {f.id for f in r.findings}


def test_result_round_trips_through_json(tmp_path):
    r = build(tmp_path, dyn=DynamicAnalysis(findings=[finding()], probes_run=["DY-001"]))
    back = json.loads(r.model_dump_json())
    assert back["verdict"] == "do_not_use" and back["findings"][0]["severity"] == "critical"
    assert back["coverage"]["mode"] == "full"
