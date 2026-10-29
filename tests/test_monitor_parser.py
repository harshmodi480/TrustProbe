"""strace parser and call attribution, against saved sample lines. No Docker."""

import pytest

from trustprobe.sandbox.monitor import (
    CallWindow,
    Event,
    attribute,
    clock_is_plausible,
    parse_trace,
    split_addr,
)

OPEN_SSH = '2417 1761720012.481233 openat(AT_FDCWD, "/home/sandbox/.ssh/id_rsa", O_RDONLY|O_CLOEXEC) = 3'
CONNECT = '2417 1761720012.502100 connect(5, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16) = -1 ENETUNREACH (Network is unreachable)'


def one(line: str) -> Event:
    events = parse_trace(line)
    assert len(events) == 1, events
    return events[0]


def test_brd_openat_example():
    ev = one(OPEN_SSH)
    assert (ev.pid, ev.ts, ev.syscall) == (2417, 1761720012.481233, "openat")
    assert ev.path == "/home/sandbox/.ssh/id_rsa"
    assert ev.flags == "O_RDONLY|O_CLOEXEC"
    assert ev.result == 3 and ev.error is None
    assert not ev.is_write


def test_brd_connect_example():
    ev = one(CONNECT)
    assert ev.syscall == "connect" and ev.family == "AF_INET"
    assert ev.addr == "93.184.216.34:443"
    assert ev.result == -1 and ev.error == "ENETUNREACH"


def test_failed_open_keeps_errno():
    ev = one('61 1793268236.133894 openat(AT_FDCWD, "/usr/lib/x.so", O_RDONLY|O_CLOEXEC) = -1 ENOENT (No such file or directory)')
    assert ev.result == -1 and ev.error == "ENOENT"


def test_open_with_write_flags_and_mode():
    ev = one('9 100.5 openat(AT_FDCWD, "/etc/cron.d/job", O_WRONLY|O_CREAT|O_TRUNC, 0644) = -1 EROFS (Read-only file system)')
    assert ev.flags == "O_WRONLY|O_CREAT|O_TRUNC"
    assert ev.is_write


def test_old_style_open():
    ev = one('9 100.5 open("/tmp/x", O_RDWR|O_CREAT, 0600) = 4')
    assert ev.syscall == "open" and ev.path == "/tmp/x" and ev.is_write


def test_relative_path_is_kept_as_given():
    assert one('9 1.5 openat(AT_FDCWD, "server.log", O_WRONLY|O_CREAT, 0666) = 3').path == "server.log"


def test_escaped_quote_in_a_path():
    assert one(r'9 1.5 openat(AT_FDCWD, "/tmp/a\"b", O_RDONLY) = 3').path == '/tmp/a"b'


def test_ipv6_connect_uses_brackets():
    ev = one('9 1.5 connect(3, {sa_family=AF_INET6, sin6_port=htons(53), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "2001:4860:4860::8888", &sin6_addr), sin6_scope_id=0}, 28) = -1 ENETUNREACH')
    assert ev.family == "AF_INET6"
    assert ev.addr == "[2001:4860:4860::8888]:53"
    assert split_addr(ev.addr) == ("2001:4860:4860::8888", "53")


def test_unix_socket_connect():
    ev = one('9 1.5 connect(3, {sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}, 110) = -1 ENOENT')
    assert ev.family == "AF_UNIX" and ev.addr == "/var/run/nscd/socket"


def test_execve_with_argv():
    ev = one('61 1.5 execve("/bin/sh", ["/bin/sh", "-c", "echo checking test; echo TPROBE-ab-42"], 0x7ffe3 /* 12 vars */) = 0')
    assert ev.path == "/bin/sh"
    assert ev.argv == ["/bin/sh", "-c", "echo checking test; echo TPROBE-ab-42"]


def test_unlink_rename_mkdir():
    assert one('9 1.5 unlink("/etc/hosts") = -1 EROFS').path == "/etc/hosts"
    assert one('9 1.5 unlinkat(AT_FDCWD, "/etc/x", 0) = -1 EROFS').path == "/etc/x"
    ev = one('9 1.5 rename("/tmp/a", "/etc/b") = -1 EROFS')
    assert (ev.path, ev.path2) == ("/tmp/a", "/etc/b") and ev.is_write
    ev = one('9 1.5 renameat2(AT_FDCWD, "/tmp/a", AT_FDCWD, "/usr/b", 0) = -1 EROFS')
    assert (ev.path, ev.path2) == ("/tmp/a", "/usr/b")
    ev = one('9 1.5 mkdirat(AT_FDCWD, "/opt/new", 0755) = -1 EROFS')
    assert ev.path == "/opt/new" and ev.is_write


def test_exit_result_question_mark():
    assert one('9 1.5 openat(AT_FDCWD, "/tmp/x", O_RDONLY) = ?').result is None


def test_unfinished_and_resumed_lines_are_joined():
    text = "\n".join([
        '9 10.000 connect(5, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("1.2.3.4")}, 16 <unfinished ...>',
        '10 10.001 openat(AT_FDCWD, "/tmp/y", O_RDONLY) = 4',
        '9 10.020 <... connect resumed>) = -1 ENETUNREACH (Network is unreachable)',
    ])
    events = parse_trace(text)
    assert [e.syscall for e in events] == ["connect", "openat"]
    connect = events[0]
    assert connect.ts == 10.000 and connect.addr == "1.2.3.4:80" and connect.error == "ENETUNREACH"


def test_noise_lines_are_ignored():
    text = "\n".join([
        '--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=62, si_uid=10001} ---',
        '61 1.5 +++ exited with 0 +++',
        "garbage that is not strace output",
        "",
        '9 2.5 mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, 3, 0) = 0x7f00',
    ])
    assert parse_trace(text) == []


def test_events_are_sorted_by_time():
    text = '9 5.0 unlink("/a") = 0\n9 1.0 unlink("/b") = 0'
    assert [e.path for e in parse_trace(text)] == ["/b", "/a"]


def test_lines_without_a_pid_are_accepted():
    assert one('1761720012.481233 openat(AT_FDCWD, "/tmp/x", O_RDONLY) = 3').pid == 0


def test_split_addr_plain():
    assert split_addr("10.0.0.1:443") == ("10.0.0.1", "443")
    assert split_addr("10.0.0.1") == ("10.0.0.1", None)


# ------------------------------------------------------------------ attribution


def ev(ts: float, syscall: str = "openat") -> Event:
    return Event(ts=ts, pid=1, syscall=syscall, path="/x", raw=f"{ts}")


WINDOWS = [CallWindow(0, "add", "tool", 100.0, 100.2), CallWindow(1, "get_weather", "tool", 101.0, 101.3)]


@pytest.mark.parametrize("ts,phase,name", [
    (100.1, "call", "add"),  # inside the call
    (99.96, "call", "add"),  # up to 0.05s before the start
    (100.6, "call", "add"),  # up to 0.5s after the end
    (101.15, "call", "get_weather"),
    (100.99, "call", "get_weather"),  # between two calls, closer to the next one's start
    (50.0, "startup", None),  # before the first MCP response and in no window
    (200.0, "idle", None),  # after everything
])
def test_attribution(ts, phase, name):
    (a,) = attribute([ev(ts)], WINDOWS, startup_until=60.0)
    assert a.phase == phase
    assert (a.call.name if a.call else None) == name


def test_attribution_targets():
    a_call, a_start, a_idle = attribute([ev(100.1), ev(50.0), ev(200.0)], WINDOWS, startup_until=60.0)
    assert (a_call.target, a_start.target, a_idle.target) == ("add", "server startup", "server (idle)")


def test_event_after_the_trailing_window_is_idle():
    (a,) = attribute([ev(100.75)], WINDOWS, startup_until=60.0)
    assert a.phase == "idle"


def test_without_a_first_response_time_nothing_is_startup():
    (a,) = attribute([ev(50.0)], WINDOWS, startup_until=None)
    assert a.phase == "idle"


def test_overlapping_windows_prefer_the_call_that_contains_the_event():
    windows = [CallWindow(0, "a", "tool", 10.0, 10.4), CallWindow(1, "b", "tool", 10.3, 10.5)]
    (inside_b,) = attribute([ev(10.45)], windows, None)
    (inside_a_only,) = attribute([ev(10.1)], windows, None)
    assert inside_b.call.name == "b" and inside_a_only.call.name == "a"


# ------------------------------------------------------------------ clock sanity


def test_clock_is_plausible():
    events = [ev(100.0), ev(105.0)]
    assert clock_is_plausible(events, 99.0, 106.0)
    assert clock_is_plausible([], 99.0, 106.0)
    assert not clock_is_plausible(events, 200.0, 210.0)  # the container clock is far off the host's
    assert not clock_is_plausible(events, 10.0, 20.0)
