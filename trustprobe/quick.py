"""`trustprobe quick`: build a default scan config for a local directory or a package.

The result is a plain dict for `parse_config`, so no config file is written (a generated file
would carry host paths). When the guesses below are not enough, write a scan.yaml instead.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

PY_ENTRYPOINTS = ("server.py", "main.py", "app.py", "__main__.py")
NODE_FALLBACK_ENTRYPOINTS = ("index.js", "server.js", "main.js")
_PYPI = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:==([A-Za-z0-9.!+_-]+))?$")
HELP = "Write a scan.yaml (see the README) and run `trustprobe scan -c scan.yaml`, or pass --command."


class QuickError(Exception):
    """The target could not be turned into a config. The message says what to do."""


def parse_package(spec: str) -> tuple[str, str, str | None]:
    """'npm:@scope/pkg@1.2.3' -> ('npm', '@scope/pkg', '1.2.3'); 'pypi:pkg==1.0' -> ('pypi', 'pkg', '1.0')."""
    kind, _, rest = spec.partition(":")
    if not rest:
        raise QuickError(f"'{spec}' needs a package name after the prefix, for example {kind}:some-server")
    if kind == "npm":
        at = rest.rfind("@")
        name, version = (rest[:at], rest[at + 1:]) if at > 0 else (rest, None)
        if not re.match(r"^(@[a-z0-9][\w.-]*/)?[a-z0-9][\w.-]*$", name):
            raise QuickError(f"'{name}' is not a valid npm package name")
        return "npm", name, version or None
    if kind == "pypi":
        m = _PYPI.match(rest)
        if not m:
            raise QuickError(f"'{rest}' is not a name or name==version; pin an exact version with ==, for example pypi:some-server==1.2.3")
        return "pypi", m.group(1), m.group(2)
    raise QuickError(f"unknown package prefix '{kind}:'; use npm: or pypi:")


def _slug(label: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", label).strip("-") or "server"


def _from_package(spec: str, command: list[str] | None) -> dict:
    kind, name, version = parse_package(spec)
    if kind == "npm":
        runtime, default = "node", ["npx", "--no-install", name]  # the package is installed in the image; no network at run time
    else:
        runtime, default = "python", [name]  # the console script has the package's name
    label = name.split("/")[-1]
    return {
        "name": f"quick: {name}{'@' + version if version else ''}",
        "server": {"source": {"type": kind, "package": name, **({"version": version} if version else {})},
                   "runtime": runtime, "command": command or default},
        "out_dir": f"out/quick-{_slug(label)}/",
    }


def _node_entry(directory: Path) -> str | None:
    pkg = directory / "package.json"
    try:
        data = json.loads(pkg.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise QuickError(f"package.json could not be read: {e}") from e
    bin_field = data.get("bin")
    entry = next(iter(bin_field.values()), None) if isinstance(bin_field, dict) else bin_field
    entry = entry or data.get("main")
    if entry:
        return str(entry)
    return next((f for f in NODE_FALLBACK_ENTRYPOINTS if (directory / f).is_file()), None)


def _from_directory(directory: Path, command: list[str] | None) -> dict:
    install: dict = {}
    if (directory / "package.json").is_file():
        runtime = "node"
        install = {"package_json": True}
        if command is None:
            entry = _node_entry(directory)
            if not entry:
                raise QuickError(f"found package.json but no entry point (bin, main, or one of {', '.join(NODE_FALLBACK_ENTRYPOINTS)}). {HELP}")
            command = ["node", entry]
    else:
        runtime = "python"
        if (directory / "requirements.txt").is_file():
            install = {"requirements": "requirements.txt"}
        if command is None:
            entry = next((f for f in PY_ENTRYPOINTS if (directory / f).is_file()), None)
            if not entry:
                raise QuickError(f"no server entry point found (looked for {', '.join(PY_ENTRYPOINTS)} and package.json). {HELP}")
            command = ["python", entry]
    return {
        "name": f"quick: {directory.name}",
        "server": {"source": {"type": "path", "path": str(directory)}, "runtime": runtime, "install": install, "command": command},
        "out_dir": f"out/quick-{_slug(directory.name)}/",
    }


def build_quick_config(target: str, *, command: list[str] | None = None, base: Path | None = None) -> dict:
    """Config dict for `target`: a directory, or `npm:<package>[@version]` / `pypi:<package>[==version]`."""
    if target.startswith(("npm:", "pypi:")):
        return _from_package(target, command)
    path = (base or Path.cwd()) / target
    if not path.exists():
        raise QuickError(f"'{target}' does not exist. Pass a server directory, or npm:<package> / pypi:<package>.")
    if not path.is_dir():
        raise QuickError(f"'{target}' is a file; pass the directory that contains the server.")
    return _from_directory(path.resolve(), command)
