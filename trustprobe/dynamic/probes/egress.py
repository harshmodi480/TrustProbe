"""DY-003: the server tried to open a network connection."""

import ipaddress

from trustprobe.dynamic.probes.base import Probe, ProbeContext, syscall_evidence, where
from trustprobe.models import Category, Confidence, Evidence, Finding, Severity
from trustprobe.sandbox.monitor import split_addr


def _loopback(addr: str) -> bool:
    host, _ = split_addr(addr)
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class EgressAttempt(Probe):
    rule_id = "DY-003"
    title = "Outbound network connection attempted"
    category = Category.network
    severity = Severity.high
    confidence = Confidence.confirmed
    description = "The server called connect() on a non-loopback network address. The sandbox has no network, so the attempt failed, but it was made."
    impact = "A real deployment would send data to that address, or fetch instructions from it."
    remediation = "Remove the outbound connection, or document it and run with policy.allow_network after review."
    requires_monitor = True

    def run(self, ctx: ProbeContext) -> list[Finding]:
        by_target: dict[str, tuple[bool, list[Evidence]]] = {}
        for att in ctx.events:
            ev = att.event
            if ev.syscall != "connect" or ev.family not in ("AF_INET", "AF_INET6") or not ev.addr or _loopback(ev.addr):
                continue
            startup, evidence = by_target.setdefault(att.target, (att.phase == "startup", []))
            outcome = ev.error or ("connected" if (ev.result or 0) >= 0 else "failed")
            # `matched` is the bare address: strace prints the IP and the port separately, so "ip:port" would not appear in the line.
            evidence.append(syscall_evidence(att, f"connect to {ev.addr} ({outcome}) {where(att)}", split_addr(ev.addr)[0]))
        findings = []
        for target, (startup, evidence) in by_target.items():
            if ctx.cfg.policy.allow_network:
                severity = Severity.info
            elif startup:
                severity = Severity.medium
            else:
                severity = Severity.high
            findings.append(self.finding(target, evidence, severity=severity))
        return findings
