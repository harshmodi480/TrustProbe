"""Keep the host out of everything the scanner writes.

Reports and logs must never contain host paths, the host username or host environment values.
Honeytoken values are fake and are deliberately left alone.
"""

from __future__ import annotations

import getpass
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Iterable

MIN_ENV_VALUE_LENGTH = 12  # shorter values are too likely to be ordinary words
MIN_USERNAME_LENGTH = 3


class Redactor:
    def __init__(self, paths: Iterable[Path | str] = ()):
        candidates: set[str] = set()
        for p in [Path.home(), Path.cwd(), Path(tempfile.gettempdir()), *map(Path, paths)]:
            s = str(p)
            if len(s) > 3:
                candidates |= {s, s.replace("\\", "/"), s.replace("/", "\\")}
        self._paths = sorted(candidates, key=len, reverse=True)

        names = {getpass.getuser(), os.environ.get("USERNAME", ""), os.environ.get("USER", ""), os.environ.get("LOGNAME", "")}
        self._names = sorted((n for n in names if len(n) >= MIN_USERNAME_LENGTH), key=len, reverse=True)

        values = {v for v in os.environ.values() if len(v) >= MIN_ENV_VALUE_LENGTH and not v.isdigit()}
        self._values = sorted(values, key=len, reverse=True)

    def text(self, s: str) -> str:
        # Paths first, longest first: a path such as TEMP is also an environment value, and replacing
        # it as a value would leave the rest of a longer path behind.
        for p in self._paths:
            s = re.sub(re.escape(p), "<host-path>", s, flags=re.IGNORECASE)
        for value in self._values:
            if value in s:
                s = s.replace(value, "<env-value>")
        for n in self._names:
            s = re.sub(rf"(?<![A-Za-z0-9]){re.escape(n)}(?![A-Za-z0-9])", "<user>", s, flags=re.IGNORECASE)
        return s

    def obj(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, list):
            return [self.obj(v) for v in value]
        if isinstance(value, dict):
            return {self.text(k) if isinstance(k, str) else k: self.obj(v) for k, v in value.items()}
        return value
