"""Auto-discovery registry for dynamic probes.

Every module in this package is imported, and every concrete `Probe` subclass found is
instantiated. To add a probe, add one Python file here; nothing else needs to change.
"""

from __future__ import annotations

import importlib
import pkgutil

from trustprobe.dynamic.probes.base import Probe, ProbeContext

__all__ = ["Probe", "ProbeContext", "discover_probes"]


def _subclasses(cls: type[Probe]) -> list[type[Probe]]:
    out = []
    for sub in cls.__subclasses__():
        out.append(sub)
        out.extend(_subclasses(sub))
    return out


def discover_probes() -> list[Probe]:
    for module in pkgutil.iter_modules(__path__):
        if module.name != "base":
            importlib.import_module(f"{__name__}.{module.name}")
    classes = {c for c in _subclasses(Probe) if "rule_id" in vars(c)}
    return sorted((c() for c in classes), key=lambda p: p.rule_id)
