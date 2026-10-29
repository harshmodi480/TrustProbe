"""Syscall monitor: parse the strace log into events and attribute them to MCP calls.

The log comes from `strace -f -ttt -s 256 -e trace=...` (see images/entrypoint.sh), so every
line is `PID EPOCH syscall(args) = result [ERRNO ...]`. Epoch timestamps are comparable with
the scanner's own call start and end times (checked against Docker Desktop's VM clock to
within tens of milliseconds, and sanity-checked per scan by `clock_is_plausible`).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

PRE_WINDOW = 0.05  # seconds before a call starts that still belong to it
POST_WINDOW = 0.5  # seconds after a call ends that still belong to it

WRITE_FLAGS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND")
OPEN_CALLS = ("open", "openat")
DELETE_CALLS = ("unlink", "unlinkat")
RENAME_CALLS = ("rename", "renameat", "renameat2")
MKDIR_CALLS = ("mkdir", "mkdirat")
TRACED = set(OPEN_CALLS) | {"connect", "execve"} | set(DELETE_CALLS) | set(RENAME_CALLS) | set(MKDIR_CALLS)


@dataclass
class Event:
    ts: float
    pid: int
    syscall: str
    path: str | None = None  # file path, or the executable for execve
    path2: str | None = None  # rename destination
    addr: str | None = None  # "ip:port" for inet sockets, the socket path for unix sockets
    family: str | None = None  # AF_INET, AF_INET6, AF_UNIX, ...
    flags: str | None = None
    argv: list[str] | None = None
    result: int | None = None
    error: str | None = None
    raw: str = ""

    @property
    def is_write(self) -> bool:
        """True for an attempt to create, modify, delete, rename or make something."""
        if self.syscall in OPEN_CALLS:
            return any(f in (self.flags or "") for f in WRITE_FLAGS)
        return self.syscall in DELETE_CALLS + RENAME_CALLS + MKDIR_CALLS


@dataclass
class CallWindow:
    index: int  # position in the client's call list
    name: str
    kind: str  # "tool" | "prompt" | "resource"
    start: float
    end: float


@dataclass
class Attributed:
    event: Event
    phase: str  # "startup" | "call" | "idle"
    call: CallWindow | None = None

    @property
    def target(self) -> str:
        """Name used for findings: the tool, prompt or resource, else the phase."""
        if self.call is not None:
            return self.call.name
        return "server startup" if self.phase == "startup" else "server (idle)"


_LINE = re.compile(r"^(?:(?P<pid>\d+)\s+)?(?P<ts>\d+\.\d+)\s+(?P<body>.*)$")
_CALL = re.compile(r"^(?P<name>[a-z_0-9]+)\((?P<args>.*)\)\s+=\s+(?P<ret>-?\d+|\?)(?:\s+(?P<err>[A-Z][A-Z0-9_]*))?")
_UNFINISHED = re.compile(r"^(?P<name>[a-z_0-9]+)\((?P<args>.*?)\s*<unfinished \.\.\.>\s*$")
_RESUMED = re.compile(r"^<\.\.\. (?P<name>[a-z_0-9]+) resumed>(?P<rest>.*)\)\s+=\s+(?P<ret>-?\d+|\?)(?:\s+(?P<err>[A-Z][A-Z0-9_]*))?")
_STR = re.compile(r'"((?:[^"\\]|\\.)*)"')
_FLAGS_AFTER_PATH = re.compile(r'"\s*,\s*(?P<flags>[A-Za-z0-9_|]+)')
_FAMILY = re.compile(r"sa_family=(AF_[A-Z0-9_]+)")
_PORT = re.compile(r"sin6?_port=htons\((\d+)\)")
_IPV4 = re.compile(r'inet_addr\("([0-9.]+)"\)')
_IPV6 = re.compile(r'inet_pton\(AF_INET6, "([0-9a-fA-F:.]+)"')
_SUN_PATH = re.compile(r'sun_path=@?"((?:[^"\\]|\\.)*)"')
_ARGV = re.compile(r"\[(.*?)\]")


def split_addr(addr: str) -> tuple[str, str | None]:
    """'93.184.216.34:443' -> ('93.184.216.34', '443'); '[::1]:53' -> ('::1', '53')."""
    if addr.startswith("["):
        host, _, rest = addr[1:].partition("]")
        return host, rest.lstrip(":") or None
    host, sep, port = addr.rpartition(":")
    return (host, port) if sep else (addr, None)


def _unescape(s: str) -> str:
    return re.sub(r"\\(.)", lambda m: {"n": "\n", "t": "\t", "r": "\r"}.get(m.group(1), m.group(1)), s)


def _strings(text: str) -> list[str]:
    return [_unescape(m.group(1)) for m in _STR.finditer(text)]


def _build(ts: float, pid: int, name: str, args: str, ret: str, err: str | None, raw: str) -> Event | None:
    if name not in TRACED:
        return None
    ev = Event(ts=ts, pid=pid, syscall=name, result=None if ret == "?" else int(ret), error=err, raw=raw)
    strings = _strings(args)
    if name in OPEN_CALLS and strings:
        ev.path = strings[0]
        m = _FLAGS_AFTER_PATH.search(args)
        ev.flags = m.group("flags") if m else None
    elif name == "connect":
        fam = _FAMILY.search(args)
        ev.family = fam.group(1) if fam else None
        if ev.family in ("AF_INET", "AF_INET6"):
            port = _PORT.search(args)
            ip = _IPV4.search(args) or _IPV6.search(args)
            if ip:
                host = f"[{ip.group(1)}]" if ev.family == "AF_INET6" else ip.group(1)
                ev.addr = f"{host}:{port.group(1)}" if port else host
        elif ev.family == "AF_UNIX":
            sun = _SUN_PATH.search(args)
            ev.addr = _unescape(sun.group(1)) if sun else None
    elif name == "execve" and strings:
        ev.path = strings[0]
        argv = _ARGV.search(args)
        ev.argv = _strings(argv.group(1)) if argv else None
    elif name in DELETE_CALLS + MKDIR_CALLS and strings:
        ev.path = strings[0]
    elif name in RENAME_CALLS and len(strings) >= 2:
        ev.path, ev.path2 = strings[0], strings[1]
    else:
        return None
    return ev


def parse_trace(text: str) -> list[Event]:
    """Parse a strace log. Unfinished/resumed pairs are joined; unknown lines are skipped."""
    events: list[Event] = []
    pending: dict[tuple[int, str], tuple[float, str, str]] = {}
    for line in text.splitlines():
        m = _LINE.match(line.strip())
        if not m:
            continue
        pid, ts, body = int(m.group("pid") or 0), float(m.group("ts")), m.group("body")
        if body.startswith(("---", "+++")):
            continue
        if (u := _UNFINISHED.match(body)):
            pending[(pid, u.group("name"))] = (ts, u.group("args"), line)
            continue
        if (r := _RESUMED.match(body)):
            started = pending.pop((pid, r.group("name")), None)
            if started:
                ev = _build(started[0], pid, r.group("name"), started[1] + r.group("rest"), r.group("ret"), r.group("err"), started[2] + " || " + line)
                if ev:
                    events.append(ev)
            continue
        if (c := _CALL.match(body)):
            ev = _build(ts, pid, c.group("name"), c.group("args"), c.group("ret"), c.group("err"), line)
            if ev:
                events.append(ev)
    events.sort(key=lambda e: e.ts)
    return events


def attribute(events: list[Event], windows: list[CallWindow], startup_until: float | None) -> list[Attributed]:
    """Assign each event to a call, to server startup, or to idle time.

    An event belongs to a call if it falls in [start - 0.05, end + 0.5]. When windows overlap,
    the call whose [start, end] is nearest wins. Events before the first MCP response (and in
    no call window) are startup; everything else is idle.
    """
    out: list[Attributed] = []
    for ev in events:
        best: tuple[float, float, CallWindow] | None = None
        for w in windows:
            if w.start - PRE_WINDOW <= ev.ts <= w.end + POST_WINDOW:
                gap = 0.0 if w.start <= ev.ts <= w.end else min(abs(ev.ts - w.start), abs(ev.ts - w.end))
                key = (gap, -w.start)
                if best is None or key < (best[0], best[1]):
                    best = (gap, -w.start, w)
        if best is not None:
            out.append(Attributed(ev, "call", best[2]))
        elif startup_until is not None and ev.ts < startup_until:
            out.append(Attributed(ev, "startup"))
        else:
            out.append(Attributed(ev, "idle"))
    return out


def clock_is_plausible(events: list[Event], host_start: float, host_end: float, slack: float = 2.0) -> bool:
    """True if the trace sits inside the host's observation window (give or take `slack` seconds).

    A larger mismatch means the container clock and the host clock disagree, so attributing
    events to calls by timestamp would be unreliable.
    """
    if not events:
        return True
    return host_start - slack <= events[0].ts and events[-1].ts <= host_end + slack
