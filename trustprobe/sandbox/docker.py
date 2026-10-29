"""Sandbox manager: build the image, start the hardened container, collect logs, tear down.

All Docker access goes through the `docker` CLI via subprocess. The scanned server is
only ever started inside the container built here, never on the host.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from trustprobe.config import ScanConfig
from trustprobe.sandbox.honeytokens import env_vars

IMAGE_REPO = "trustprobe-sandbox"
IMAGES_DIR = Path(__file__).parent / "images"
INSTALL_MARKER = "# @@INSTALL@@"
CONTAINER_UID = "10001"

# Names that are never copied into the build context.
_SKIP_NAMES = {".git", "__pycache__", ".venv", "node_modules", ".pytest_cache"}
# Package names, versions and requirements paths end up in a Dockerfile exec-form RUN line.
_SAFE_SPEC = re.compile(r"^[A-Za-z0-9@/._~^<>=!+*-]+$")


class SandboxError(Exception):
    """Docker or sandbox failure. The message says what to fix."""


# --------------------------------------------------------------------------- docker CLI


def docker_path() -> str:
    path = shutil.which("docker")
    if path is None:
        raise SandboxError("docker CLI not found on PATH; install Docker and make sure `docker` runs")
    return path


def run_docker(args: list[str], *, timeout: float | None = None) -> subprocess.CompletedProcess[str]:
    """Run a docker CLI command and capture its output as text."""
    try:
        return subprocess.run(
            [docker_path(), *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdin=subprocess.DEVNULL,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as e:
        raise SandboxError(f"docker {args[0]} timed out after {timeout}s") from e
    except OSError as e:
        raise SandboxError(f"could not run docker: {e}") from e


def docker_available() -> tuple[bool, str]:
    """(ok, server version or reason). Does not start anything."""
    try:
        proc = run_docker(["version", "--format", "{{.Server.Version}}"], timeout=20)
    except SandboxError as e:
        return False, str(e)
    if proc.returncode != 0 or not proc.stdout.strip():
        return False, "the Docker daemon is not reachable; start Docker Desktop (or the docker service) and retry"
    return True, proc.stdout.strip()


def remove_container(name: str) -> None:
    """Kill and remove a container; never raises."""
    for args in (["kill", name], ["rm", "-f", name]):
        try:
            run_docker(args, timeout=30)
        except SandboxError:
            pass


def remove_volume(name: str) -> None:
    """Remove a named volume; never raises."""
    try:
        run_docker(["volume", "rm", "-f", name], timeout=30)
    except SandboxError:
        pass


# --------------------------------------------------------------------------- image build


def _safe(value: str, field: str) -> str:
    if not _SAFE_SPEC.match(value):
        raise SandboxError(f"{field}: '{value}' contains characters that are not allowed in a package spec")
    return value


def install_lines(cfg: ScanConfig) -> list[str]:
    """Dockerfile RUN lines (exec form) that install the server's dependencies."""
    inst = cfg.server.install
    src = cfg.server.source
    runtime = cfg.runtime
    lines: list[list[str]] = []

    if src.type == "pypi":
        spec = _safe(src.package or "", "server.source.package")
        if src.version:
            spec += f"=={_safe(src.version, 'server.source.version')}"
        lines.append(["pip", "install", "--no-cache-dir", spec])
    elif src.type == "npm":
        spec = _safe(src.package or "", "server.source.package")
        if src.version:
            spec += f"@{_safe(src.version, 'server.source.version')}"
        lines.append(["npm", "install", "--no-audit", "--no-fund", "--prefix", "/app", spec])
    elif runtime == "python" and inst.requirements:
        req = _safe(inst.requirements, "server.install.requirements")
        lines.append(["pip", "install", "--no-cache-dir", "-r", f"/app/{req}"])
    elif runtime == "node" and inst.package_json:
        lines.append(["npm", "install", "--omit=dev", "--no-audit", "--no-fund", "--prefix", "/app"])

    return ["RUN " + json.dumps(parts) for parts in lines]


def _iter_files(root: Path):
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root)
        if any(part in _SKIP_NAMES for part in rel.parts):
            continue
        yield p, rel


def hash_tree(root: Path) -> str:
    """Content hash of a directory (paths, file bytes, symlink targets)."""
    h = hashlib.sha256()
    for p, rel in _iter_files(root):
        h.update(rel.as_posix().encode())
        if p.is_symlink():
            h.update(b"L" + str(p.readlink()).encode())
        elif p.is_file():
            h.update(b"F" + p.read_bytes())
    return h.hexdigest()


def render_dockerfile(cfg: ScanConfig) -> str:
    template = (IMAGES_DIR / f"{cfg.runtime}.Dockerfile").read_text(encoding="utf-8")
    if INSTALL_MARKER not in template:
        raise SandboxError(f"{cfg.runtime}.Dockerfile is missing the {INSTALL_MARKER} marker")
    return template.replace(INSTALL_MARKER, "\n".join(install_lines(cfg)))


def _entrypoint_bytes() -> bytes:
    """entrypoint.sh with LF line endings, whatever the checkout did to it (Windows)."""
    return (IMAGES_DIR / "entrypoint.sh").read_bytes().replace(b"\r\n", b"\n")


def image_tag(cfg: ScanConfig) -> str:
    """Tag derived from everything that goes into the image, so unchanged inputs hit the cache."""
    h = hashlib.sha256()
    src = cfg.source_path
    if src is not None:
        h.update(hash_tree(src).encode())
    h.update(render_dockerfile(cfg).encode())
    h.update(_entrypoint_bytes())
    return f"{IMAGE_REPO}:{h.hexdigest()[:12]}"


def build_context(cfg: ScanConfig, dest: Path) -> None:
    """Lay out the docker build context: Dockerfile, entrypoint.sh, and the server in app/."""
    app = dest / "app"
    src = cfg.source_path
    if src is not None:
        shutil.copytree(src, app, symlinks=True, ignore=shutil.ignore_patterns(*_SKIP_NAMES))
    else:
        app.mkdir(parents=True)
    (app / ".trustprobe-keep").write_text("", encoding="utf-8")  # COPY needs a non-empty source
    (dest / "Dockerfile").write_text(render_dockerfile(cfg), encoding="utf-8", newline="\n")
    (dest / "entrypoint.sh").write_bytes(_entrypoint_bytes())


def image_exists(tag: str) -> bool:
    return run_docker(["image", "inspect", tag], timeout=30).returncode == 0


def ensure_image(cfg: ScanConfig) -> tuple[str, bool]:
    """Return (tag, built_now). The build is the only step that has network access."""
    tag = image_tag(cfg)
    if image_exists(tag):
        return tag, False
    with tempfile.TemporaryDirectory(prefix="trustprobe-build-") as td:
        ctx = Path(td)
        build_context(cfg, ctx)
        proc = run_docker(["build", "--tag", tag, str(ctx)], timeout=900)
    if proc.returncode != 0:
        tail = "\n".join((proc.stdout + proc.stderr).strip().splitlines()[-15:])
        raise SandboxError(f"image build failed (is the server's install step valid?):\n{tail}")
    return tag, True


# --------------------------------------------------------------------------- run command


def build_run_command(
    *,
    tag: str,
    nonce: str,
    audit_volume: str,
    server_command: list[str],
    name: str | None = None,
    cap_ptrace: bool = False,
    strace: bool = True,
    detach: bool = False,
    docker: str = "docker",
) -> list[str]:
    """The hardened `docker run` command (BRD 8.2).

    Every `-e` carries an explicit value: host environment variables are never forwarded.
    The syscall log goes to a Docker-managed named volume mounted at /audit (the image
    pre-creates /audit owned by the sandbox user). The BRD used a host bind mount here; that
    needs Docker Desktop file-sharing approval per folder on Windows, a named volume does not.
    """
    cmd = [
        docker, "run", "--rm", "-d" if detach else "-i", "--name", name or f"tp-{nonce}",
        "--network", "none", "--read-only",
        "--tmpfs", "/tmp:rw,size=64m",
        "--tmpfs", "/workspace:rw,size=64m",
        "--tmpfs", f"/home/sandbox:rw,size=8m,uid={CONTAINER_UID},gid={CONTAINER_UID}",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--pids-limit", "128", "--memory", "512m", "--cpus", "1",
        "--user", f"{CONTAINER_UID}:{CONTAINER_UID}",
        "-v", f"{audit_volume}:/audit:rw",
        "-e", f"TP_NONCE={nonce}",
        "-e", "HOME=/home/sandbox",
        "-e", f"TP_STRACE={'1' if strace else '0'}",
    ]
    for key, value in env_vars(nonce).items():
        cmd += ["-e", f"{key}={value}"]
    if cap_ptrace:
        cmd += ["--cap-add", "SYS_PTRACE"]
    cmd += [tag, "/entrypoint.sh", *server_command]
    return cmd


# --------------------------------------------------------------------------- sandbox


@dataclass
class MonitorMode:
    enabled: bool  # run the server under strace
    cap_ptrace: bool  # needed --cap-add SYS_PTRACE
    note: str | None  # shown in coverage.monitor_note


class Watchdog:
    """Hard wall-clock limit: kills the container when the time is up."""

    def __init__(self, container: str, seconds: float):
        self.container = container
        self.fired = False
        self._timer = threading.Timer(seconds, self._fire)
        self._timer.daemon = True

    def _fire(self) -> None:
        self.fired = True
        remove_container(self.container)

    def start(self) -> None:
        self._timer.start()

    def cancel(self) -> None:
        self._timer.cancel()


class Sandbox:
    def __init__(self, cfg: ScanConfig, nonce: str, out_dir: Path):
        self.cfg = cfg
        self.nonce = nonce
        self.out_dir = out_dir
        self.audit_dir = out_dir / "audit"  # host copy of the syscall log, written by read_trace()
        self.audit_volume = f"tp-audit-{nonce}"
        self.name = f"tp-{nonce}"
        self._trace: str | None = None
        self.tag: str | None = None
        self.built_now = False
        self.monitor = MonitorMode(enabled=False, cap_ptrace=False, note=None)
        self.watchdog: Watchdog | None = None

    def prepare(self, log: Callable[[str], None] = lambda _m: None) -> None:
        """Check Docker, build (or reuse) the image, and decide how to run strace."""
        ok, info = docker_available()
        if not ok:
            raise SandboxError(info)
        self.tag, self.built_now = ensure_image(self.cfg)
        self.audit_dir.mkdir(parents=True, exist_ok=True)
        stale = self.audit_dir / "trace.log"
        if stale.exists():
            stale.unlink()
        created = run_docker(["volume", "create", self.audit_volume], timeout=30)
        if created.returncode != 0:
            raise SandboxError(f"could not create the audit volume: {created.stderr.strip()}")
        self.monitor = self._check_strace()
        log(f"image {self.tag} ({'built' if self.built_now else 'cached'}); monitor={self.monitor}")

    def _check_strace(self) -> MonitorMode:
        """Try strace without extra capabilities first; retry once with SYS_PTRACE.

        A docker-level failure (exit 125, for example a volume or daemon error) is raised, not
        reported as "strace unavailable": that would silently weaken the scan.
        """
        assert self.tag
        for cap in (False, True):
            cmd = build_run_command(
                tag=self.tag, nonce=self.nonce, audit_volume=self.audit_volume,
                server_command=["--check-strace"], name=f"{self.name}-check", cap_ptrace=cap,
            )
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL, timeout=60)
            except (subprocess.TimeoutExpired, OSError):
                proc = None
            finally:
                remove_container(f"{self.name}-check")
            if proc is not None and proc.returncode == 125:
                raise SandboxError(f"docker could not start the sandbox container: {proc.stderr.strip()}")
            if proc is not None and "STRACE_OK" in proc.stdout:
                return MonitorMode(True, cap, "ran with SYS_PTRACE" if cap else None)
        return MonitorMode(False, False, "strace unavailable in sandbox")

    def server_process(self) -> tuple[str, list[str]]:
        """(executable, args) of the `docker run -i` process the MCP client talks to."""
        if self.tag is None:
            raise SandboxError("sandbox not prepared")
        cmd = build_run_command(
            tag=self.tag, nonce=self.nonce, audit_volume=self.audit_volume,
            server_command=list(self.cfg.server.command), name=self.name,
            cap_ptrace=self.monitor.cap_ptrace, strace=self.monitor.enabled, docker=docker_path(),
        )
        return cmd[0], cmd[1:]

    def start_watchdog(self) -> None:
        self.watchdog = Watchdog(self.name, self.cfg.scan.total_timeout_s)
        self.watchdog.start()

    @property
    def timed_out(self) -> bool:
        return bool(self.watchdog and self.watchdog.fired)

    def read_trace(self) -> str:
        """The strace log from the audit volume. Fetched once, cached, and copied to out/audit/."""
        if self._trace is None:
            text = ""
            if self.tag is not None:
                proc = run_docker(
                    ["run", "--rm", "--network", "none", "--user", f"{CONTAINER_UID}:{CONTAINER_UID}",
                     "-v", f"{self.audit_volume}:/audit:ro", "--entrypoint", "cat", self.tag, "/audit/trace.log"],
                    timeout=60,
                )
                if proc.returncode == 0:
                    text = proc.stdout
            self._trace = text
            if text:
                (self.audit_dir / "trace.log").write_text(text, encoding="utf-8")
        return self._trace

    def cleanup(self) -> None:
        """Always safe to call: stops the watchdog, removes the container and the audit volume."""
        if self.watchdog:
            self.watchdog.cancel()
        remove_container(self.name)
        remove_container(f"{self.name}-check")
        remove_volume(self.audit_volume)
