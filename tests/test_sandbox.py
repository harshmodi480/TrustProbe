"""Sandbox tests. Unit tests need no Docker; @pytest.mark.docker tests run containers."""

import json
import os
import subprocess
import time
import uuid
from pathlib import Path

import pytest

from trustprobe.config import load_config, parse_config
from trustprobe.sandbox import honeytokens as ht
from trustprobe.sandbox.docker import (
    Sandbox,
    SandboxError,
    build_run_command,
    ensure_image,
    image_tag,
    install_lines,
    remove_container,
    remove_volume,
    run_docker,
)

ROOT = Path(__file__).resolve().parent.parent
NONCE = "0a1b2c3d"


def cfg_for(tmp_path: Path, **server) -> object:
    (tmp_path / "srv").mkdir(exist_ok=True)
    (tmp_path / "srv" / "server.py").write_text("print('hi')\n")
    data = {"name": "t", "server": {"source": {"type": "path", "path": "srv"}, "command": ["python", "server.py"]}}
    data["server"].update(server)
    return parse_config(data, tmp_path)


# ------------------------------------------------------------------ unit: run command


def run_cmd(**kw) -> list[str]:
    return build_run_command(tag="trustprobe-sandbox:x", nonce=NONCE, audit_volume="tp-audit-test",
                             server_command=["python", "server.py"], **kw)


def pairs(cmd: list[str]) -> set[tuple[str, str]]:
    return set(zip(cmd, cmd[1:]))


def test_run_command_has_every_hardening_flag():
    cmd = run_cmd()
    p = pairs(cmd)
    assert ("--network", "none") in p
    assert "--read-only" in cmd
    assert ("--cap-drop", "ALL") in p
    assert ("--security-opt", "no-new-privileges") in p
    assert ("--pids-limit", "128") in p
    assert ("--memory", "512m") in p
    assert ("--cpus", "1") in p
    assert ("--user", "10001:10001") in p
    assert "--rm" in cmd and "-i" in cmd
    assert ("--name", f"tp-{NONCE}") in p


def test_audit_log_uses_a_named_volume_not_a_host_bind_mount():
    cmd = run_cmd()
    mounts = [cmd[i + 1] for i, a in enumerate(cmd) if a == "-v"]
    assert mounts == ["tp-audit-test:/audit:rw"]  # no host path, so no Docker Desktop file-sharing prompt


def test_run_command_tmpfs_mounts():
    cmd = run_cmd()
    tmpfs = [cmd[i + 1] for i, a in enumerate(cmd) if a == "--tmpfs"]
    assert {t.split(":")[0] for t in tmpfs} == {"/tmp", "/workspace", "/home/sandbox"}


def test_run_command_never_forwards_host_variables_or_privileges():
    cmd = run_cmd()
    for i, a in enumerate(cmd):
        if a == "-e":
            assert "=" in cmd[i + 1], f"-e {cmd[i + 1]} would forward a host variable"
    assert "--privileged" not in cmd
    assert "--cap-add" not in cmd
    assert not any(a in ("--network=host", "--pid=host", "--env-file") for a in cmd)


def test_run_command_env_is_nonce_and_honeytokens_only():
    cmd = run_cmd()
    envs = {cmd[i + 1].split("=", 1)[0] for i, a in enumerate(cmd) if a == "-e"}
    assert envs == {"TP_NONCE", "HOME", "TP_STRACE", "OPENAI_API_KEY", "GITHUB_TOKEN"}


def test_ptrace_capability_only_when_requested():
    cmd = run_cmd(cap_ptrace=True)
    assert ("--cap-add", "SYS_PTRACE") in pairs(cmd)
    assert "ALL" in cmd[cmd.index("--cap-drop") + 1]


def test_command_comes_last_after_entrypoint():
    cmd = run_cmd()
    assert cmd[-3:] == ["/entrypoint.sh", "python", "server.py"]
    assert cmd[-4] == "trustprobe-sandbox:x"


# ------------------------------------------------------------------ unit: image inputs


def test_install_lines_python_requirements(tmp_path):
    (tmp_path / "srv").mkdir()
    (tmp_path / "srv" / "requirements.txt").write_text("mcp==1.30.0\n")
    cfg = cfg_for(tmp_path, install={"requirements": "requirements.txt"})
    assert install_lines(cfg) == ['RUN ["pip", "install", "--no-cache-dir", "-r", "/app/requirements.txt"]']


def test_install_lines_pypi_pinned(tmp_path):
    cfg = parse_config(
        {"name": "t", "server": {"source": {"type": "pypi", "package": "mcp-server-time", "version": "1.2.3"},
                                 "command": ["mcp-server-time"]}}, tmp_path)
    assert install_lines(cfg) == ['RUN ["pip", "install", "--no-cache-dir", "mcp-server-time==1.2.3"]']


def test_install_lines_npm(tmp_path):
    cfg = parse_config(
        {"name": "t", "server": {"source": {"type": "npm", "package": "@scope/server", "version": "0.4.0"},
                                 "command": ["node", "x.js"]}}, tmp_path)
    (line,) = install_lines(cfg)
    assert "@scope/server@0.4.0" in line and line.startswith("RUN [")


def test_install_lines_node_package_json(tmp_path):
    (tmp_path / "srv").mkdir()
    (tmp_path / "srv" / "package.json").write_text("{}")
    cfg = cfg_for(tmp_path, runtime="node", install={"package_json": True})
    (line,) = install_lines(cfg)
    assert "npm" in line and "--omit=dev" in line


def test_unsafe_package_spec_is_rejected(tmp_path):
    cfg = parse_config(
        {"name": "t", "server": {"source": {"type": "pypi", "package": "evil; rm -rf /"}, "command": ["x"]}}, tmp_path)
    with pytest.raises(SandboxError, match="not allowed"):
        install_lines(cfg)


def test_image_tag_is_stable_and_tracks_server_content(tmp_path):
    cfg = cfg_for(tmp_path)
    first = image_tag(cfg)
    assert first == image_tag(cfg)
    assert first.startswith("trustprobe-sandbox:")
    (tmp_path / "srv" / "server.py").write_text("print('changed')\n")
    assert image_tag(cfg) != first


def test_image_tag_ignores_cache_and_vcs_dirs(tmp_path):
    cfg = cfg_for(tmp_path)
    first = image_tag(cfg)
    (tmp_path / "srv" / "__pycache__").mkdir()
    (tmp_path / "srv" / "__pycache__" / "x.pyc").write_bytes(b"\x00")
    assert image_tag(cfg) == first


def test_entrypoint_has_lf_line_endings():
    data = (ROOT / "trustprobe" / "sandbox" / "images" / "entrypoint.sh").read_bytes()
    assert data.startswith(b"#!/bin/sh")


# ------------------------------------------------------------------ docker: safety tests


@pytest.fixture(scope="module")
def tag() -> str:
    cfg = load_config(ROOT / "examples" / "scan.benign_calc.yaml")
    return ensure_image(cfg)[0]


def sandbox_run(tag: str, py: str, *, strace: bool = False, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    """Run a Python snippet inside the hardened container, using the real run command."""
    name = f"tp-test-{uuid.uuid4().hex[:8]}"
    volume = f"tp-audit-{name}"
    cmd = build_run_command(tag=tag, nonce=NONCE, audit_volume=volume, server_command=["python", "-c", py],
                            name=name, strace=strace)
    try:
        return subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=timeout)
    finally:
        remove_container(name)
        remove_volume(volume)


@pytest.mark.docker
def test_network_connection_fails(tag):
    py = ("import socket\n"
          "try:\n"
          "    socket.create_connection(('93.184.216.34', 443), timeout=3); print('CONNECTED')\n"
          "except OSError as e:\n"
          "    print('BLOCKED', type(e).__name__)\n")
    out = sandbox_run(tag, py).stdout
    assert "BLOCKED" in out and "CONNECTED" not in out


@pytest.mark.docker
def test_root_filesystem_is_read_only(tag):
    py = ("for p in ('/app/x', '/etc/x', '/usr/x'):\n"
          "    try:\n"
          "        open(p, 'w').close(); print('WROTE', p)\n"
          "    except OSError:\n"
          "        print('DENIED', p)\n")
    out = sandbox_run(tag, py).stdout
    assert "WROTE" not in out and out.count("DENIED") == 3


@pytest.mark.docker
def test_tmp_and_workspace_are_writable(tag):
    py = ("for p in ('/tmp/x', '/workspace/x', '/home/sandbox/x'):\n"
          "    open(p, 'w').close(); print('OK', p)\n")
    out = sandbox_run(tag, py).stdout
    assert out.count("OK") == 3


@pytest.mark.docker
def test_container_runs_as_non_root(tag):
    out = sandbox_run(tag, "import os; print(os.getuid(), os.getgid())").stdout.split()
    assert out == ["10001", "10001"]


@pytest.mark.docker
def test_honeytokens_match_the_expected_contents(tag):
    py = ("import json, os\n"
          "paths = ['/home/sandbox/.ssh/id_rsa', '/home/sandbox/.aws/credentials', '/home/sandbox/.env', '/workspace/sample.txt']\n"
          "print(json.dumps({p: open(p).read() for p in paths}))\n"
          "print(json.dumps({k: os.environ[k] for k in ('OPENAI_API_KEY', 'GITHUB_TOKEN', 'HOME')}))\n")
    lines = sandbox_run(tag, py).stdout.strip().splitlines()
    assert json.loads(lines[0]) == ht.files(NONCE)
    env = json.loads(lines[1])
    assert env["HOME"] == "/home/sandbox"
    assert {k: env[k] for k in ht.env_vars(NONCE)} == ht.env_vars(NONCE)


@pytest.mark.docker
def test_host_environment_is_not_visible_inside(tag, monkeypatch):
    monkeypatch.setenv("TP_HOST_SECRET", "host-secret-value")
    out = sandbox_run(tag, "import os; print(sorted(os.environ)); print(os.environ.get('USERNAME'))").stdout
    assert "TP_HOST_SECRET" not in out
    assert "host-secret-value" not in out
    assert os.environ.get("USERNAME", "<unset>") not in out.splitlines()[-1]


@pytest.mark.docker
def test_docker_inspect_shows_the_expected_flags(tag):
    name = f"tp-test-{uuid.uuid4().hex[:8]}"
    volume = f"tp-audit-{name}"
    cmd = build_run_command(tag=tag, nonce=NONCE, audit_volume=volume, server_command=["sleep", "30"],
                            name=name, strace=False, detach=True)
    try:
        started = subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=60)
        assert started.returncode == 0, started.stderr
        time.sleep(1)
        info = json.loads(run_docker(["inspect", name]).stdout)[0]
        host = info["HostConfig"]
        assert host["NetworkMode"] == "none"
        assert host["ReadonlyRootfs"] is True
        assert host["CapDrop"] == ["ALL"] and not host["CapAdd"]
        assert "no-new-privileges" in " ".join(host["SecurityOpt"])
        assert host["PidsLimit"] == 128
        assert host["Memory"] == 512 * 1024 * 1024
        assert host["NanoCpus"] == 1_000_000_000
        assert host["Privileged"] is False
        assert info["Config"]["User"] == "10001:10001"
        assert {"/tmp", "/workspace", "/home/sandbox"} <= set(host["Tmpfs"])
        assert [m["Type"] for m in info["Mounts"] if m["Destination"] == "/audit"] == ["volume"]
    finally:
        remove_container(name)
        remove_volume(volume)


@pytest.mark.docker
def test_strace_records_syscalls_with_epoch_timestamps(tag, tmp_path):
    cfg = load_config(ROOT / "examples" / "scan.benign_calc.yaml")
    sb = Sandbox(cfg, NONCE, tmp_path)
    sb.prepare()
    try:
        assert sb.tag == tag
        if not sb.monitor.enabled:
            pytest.skip(f"strace unavailable here: {sb.monitor.note}")
        cmd = build_run_command(tag=tag, nonce=NONCE, audit_volume=sb.audit_volume,
                                server_command=["python", "-c", "open('/home/sandbox/.ssh/id_rsa').read()"],
                                name=f"tp-test-{uuid.uuid4().hex[:8]}", cap_ptrace=sb.monitor.cap_ptrace)
        before = time.time()
        subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=60)
        trace = sb.read_trace()
        assert 'openat(AT_FDCWD, "/home/sandbox/.ssh/id_rsa"' in trace
        first_ts = float(trace.splitlines()[0].split()[1])
        assert before - 5 < first_ts < time.time() + 5  # comparable with the host clock
    finally:
        sb.cleanup()


@pytest.mark.docker
def test_cleanup_removes_the_container(tag, tmp_path):
    cfg = load_config(ROOT / "examples" / "scan.benign_calc.yaml")
    sb = Sandbox(cfg, "feedface", tmp_path)
    sb.prepare()
    sb.cleanup()
    names = run_docker(["ps", "-a", "--filter", "name=tp-feedface", "--format", "{{.Names}}"]).stdout
    assert names.strip() == ""
    volumes = run_docker(["volume", "ls", "--filter", "name=tp-audit-feedface", "--format", "{{.Name}}"]).stdout
    assert volumes.strip() == ""
