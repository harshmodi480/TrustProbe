from __future__ import annotations

import asyncio
import json
import os
import re
import subprocess
import sys
import threading
import uuid
from pathlib import Path
from typing import AsyncIterator, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, field_validator
from sse_starlette.sse import EventSourceResponse

ROOT = Path(__file__).parent
SERVERS_FILE = Path(os.environ.get("SERVERS_FILE", ROOT / "ui_servers.json"))
SERVERS_FILE.parent.mkdir(parents=True, exist_ok=True)
OUT_DIR = Path(os.environ.get("OUT_DIR", ROOT / "out"))
OUT_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(title="TrustProbe")

# scan_id -> {lines, proc, done, returncode}
_scans: dict[str, dict] = {}
_MAX_SCANS = 50

# active scan per server-id (prevents concurrent scans)
_active: dict[int, str] = {}
_lock = threading.Lock()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _load() -> list[dict]:
    if SERVERS_FILE.exists():
        try:
            return json.loads(SERVERS_FILE.read_text())
        except Exception:
            return []
    return []


def _save(servers: list[dict]) -> None:
    SERVERS_FILE.write_text(json.dumps(servers, indent=2))


def _slug(name: str) -> str:
    return re.sub(r"[^\w\-]", "_", name)[:64]


def _build_cmd(server: dict, mode_override: str | None = None) -> list[str]:
    """Build a trustprobe quick command — auto-detects runtime, command, install."""
    source_type = server["source_type"]
    source = server["source"].strip()
    mode = mode_override or server.get("mode", "full")
    out = OUT_DIR / _slug(server["name"])

    if source_type == "npm":
        target = f"npm:{source}"
    elif source_type == "pypi":
        target = f"pypi:{source}"
    else:
        target = source  # local path — trustprobe auto-detects from directory

    cmd = [sys.executable, "-m", "trustprobe", "quick", target,
           "--yes", "--out", str(out)]
    if mode == "static":
        cmd.append("--static-only")
    server_args = server.get("server_args", "").strip()
    if server_args:
        cmd += ["--command", server_args]
    return cmd


def _prune_scans() -> None:
    if len(_scans) > _MAX_SCANS:
        done = [k for k, v in _scans.items() if v.get("done")]
        for k in done[:len(_scans) - _MAX_SCANS]:
            _scans.pop(k, None)


def _launch(cmd: list[str], server_id: int) -> str:
    scan_id = str(uuid.uuid4())
    _scans[scan_id] = {"lines": [], "proc": None, "done": False, "returncode": 0}
    _prune_scans()

    with _lock:
        _active[server_id] = scan_id

    def _run() -> None:
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True, bufsize=1)
            _scans[scan_id]["proc"] = proc
            for line in proc.stdout:
                _scans[scan_id]["lines"].append(line)
            proc.wait()
            _scans[scan_id]["returncode"] = proc.returncode
        except FileNotFoundError as exc:
            _scans[scan_id]["lines"].append(
                f"error: command not found — {exc}\n"
                "hint: ensure Node.js/npm (for npm sources) or Python (for path sources) is installed and on PATH\n"
            )
            _scans[scan_id]["returncode"] = 3
        except Exception as exc:
            _scans[scan_id]["lines"].append(f"error: {exc}\n")
            _scans[scan_id]["returncode"] = 3
        finally:
            _scans[scan_id]["done"] = True
            with _lock:
                if _active.get(server_id) == scan_id:
                    _active.pop(server_id, None)

    threading.Thread(target=_run, daemon=True).start()
    return scan_id


# ── Models ────────────────────────────────────────────────────────────────────

class ServerIn(BaseModel):
    name: str
    source_type: str
    source: str
    mode: str = "full"
    server_args: str = ""

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        v = v.strip()
        if not v or len(v) > 100:
            raise ValueError("Name must be 1–100 characters")
        if not re.match(r"^[\w\s\-\.@/]+$", v):
            raise ValueError("Name contains invalid characters")
        return v

    @field_validator("source_type")
    @classmethod
    def _src(cls, v: str) -> str:
        if v not in ("npm", "pypi", "path"):
            raise ValueError("source_type must be npm, pypi, or path")
        return v

    @field_validator("source")
    @classmethod
    def _source(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Source is required")
        return v

    @field_validator("mode")
    @classmethod
    def _mode(cls, v: str) -> str:
        if v not in ("full", "static"):
            raise ValueError("mode must be full or static")
        return v


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/api/servers")
def list_servers():
    return [{"id": i, **s} for i, s in enumerate(_load())]


@app.post("/api/servers", status_code=201)
def add_server(data: ServerIn):
    servers = _load()
    if any(s["name"].lower() == data.name.lower() for s in servers):
        raise HTTPException(409, "A server with this name already exists")
    entry = data.model_dump()
    servers.append(entry)
    _save(servers)
    return {"id": len(servers) - 1, **entry}


@app.delete("/api/servers/{sid}")
def delete_server(sid: int):
    servers = _load()
    if not (0 <= sid < len(servers)):
        raise HTTPException(404, "Server not found")
    with _lock:
        if sid in _active:
            raise HTTPException(409, "Stop the running scan before deleting")
    name = servers.pop(sid)["name"]
    _save(servers)
    return {"deleted": name}


@app.post("/api/scan/{sid}")
def start_scan(sid: int, mode: Optional[str] = None):
    import shutil
    servers = _load()
    if not (0 <= sid < len(servers)):
        raise HTTPException(404, "Server not found")
    with _lock:
        if sid in _active:
            raise HTTPException(409, "A scan is already running for this server — stop it first")
    server = servers[sid]
    # Validate path sources exist before launching
    if server["source_type"] == "path":
        p = Path(server["source"])
        if not p.exists():
            raise HTTPException(400, f"Server directory not found: {server['source']}")
        if not p.is_dir():
            raise HTTPException(400, f"Server source must be a directory, not a file: {server['source']}")
    cmd = _build_cmd(server, mode_override=mode)
    return {"scan_id": _launch(cmd, sid)}


@app.post("/api/scan/{scan_id}/stop")
def stop_scan(scan_id: str):
    entry = _scans.get(scan_id)
    if not entry:
        raise HTTPException(404, "Scan not found")
    proc = entry.get("proc")
    if proc and proc.poll() is None:
        proc.terminate()
    entry["done"] = True
    entry["returncode"] = -1
    return {"stopped": True}


@app.get("/api/scan/{scan_id}/stream")
async def stream(scan_id: str, request: Request):
    if scan_id not in _scans:
        raise HTTPException(404, "Scan not found")

    async def gen() -> AsyncIterator[dict]:
        sent = 0
        while True:
            if await request.is_disconnected():
                break
            entry = _scans.get(scan_id, {})
            lines = entry.get("lines", [])
            while sent < len(lines):
                yield {"data": lines[sent].rstrip()}
                sent += 1
            if entry.get("done"):
                lines = entry.get("lines", [])
                while sent < len(lines):
                    yield {"data": lines[sent].rstrip()}
                    sent += 1
                yield {"event": "done", "data": str(entry.get("returncode", 0))}
                break
            await asyncio.sleep(0.1)

    return EventSourceResponse(gen())


@app.get("/api/results/{sid}")
def get_results(sid: int):
    servers = _load()
    if not (0 <= sid < len(servers)):
        raise HTTPException(404, "Server not found")
    f = OUT_DIR / _slug(servers[sid]["name"]) / "results.json"
    if not f.exists():
        raise HTTPException(404, "No results yet — run a scan first")
    try:
        return json.loads(f.read_text())
    except Exception as e:
        raise HTTPException(500, f"Failed to read results: {e}")


@app.get("/api/docker")
def docker_status():
    import shutil
    if not shutil.which("docker"):
        return {"available": False, "reason": "Docker not found — is Docker Desktop running?"}
    try:
        r = subprocess.run(["docker", "info"], capture_output=True, timeout=5)
        ok = r.returncode == 0
        return {"available": ok, "reason": None if ok else "Docker daemon not running — start Docker Desktop"}
    except subprocess.TimeoutExpired:
        return {"available": False, "reason": "Docker not responding (timeout)"}
    except Exception as e:
        return {"available": False, "reason": str(e)}


@app.get("/api/browse")
def browse_directory():
    """Open a native directory picker and return the chosen path. Only works when running locally."""
    try:
        import tkinter as tk
        from tkinter import filedialog
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        path = filedialog.askdirectory(title="Select MCP Server Directory")
        root.destroy()
        if not path:
            return {"path": None}
        return {"path": path}
    except Exception as e:
        raise HTTPException(400, f"Directory browser unavailable: {e}. Enter the path manually.")


@app.get("/report/{sid}")
def get_report(sid: int):
    servers = _load()
    if not (0 <= sid < len(servers)):
        raise HTTPException(404, "Server not found")
    report = OUT_DIR / _slug(servers[sid]["name"]) / "report.html"
    if not report.exists():
        raise HTTPException(404, "No report yet — run a scan first")
    return FileResponse(str(report), media_type="text/html")


app.mount("/", StaticFiles(directory=str(ROOT / "static"), html=True), name="static")
