"""Fake secrets planted in the sandbox, and helpers to spot them in any text.

Every fake value contains the marker HONEY-<nonce>-<KIND>, so one regex finds it
anywhere. The container entrypoint writes the files from TP_NONCE; the scanner passes
the environment values with explicit `-e NAME=value` flags (never by forwarding host
variables).
"""

from __future__ import annotations

import posixpath
import re

SANDBOX_HOME = "/home/sandbox"

# Paths under these prefixes count as "honeytoken files" for DY-002.
HONEYTOKEN_PATH_PREFIXES = (
    f"{SANDBOX_HOME}/.ssh",
    f"{SANDBOX_HOME}/.aws",
    f"{SANDBOX_HOME}/.env",
)


def is_honeytoken_path(path: str | None) -> bool:
    """True if `path` is one of the planted secret files (or inside one of the planted directories)."""
    if not path:
        return False
    norm = posixpath.normpath(path)
    return any(norm == p or norm.startswith(p + "/") for p in HONEYTOKEN_PATH_PREFIXES)


def marker(nonce: str, kind: str) -> str:
    return f"HONEY-{nonce}-{kind}"


def marker_regex(nonce: str) -> re.Pattern[str]:
    return re.compile(rf"HONEY-{re.escape(nonce)}-[A-Z0-9]+")


def find_markers(text: str, nonce: str) -> list[str]:
    """All distinct honeytoken markers in `text`, in order of first appearance."""
    seen: dict[str, None] = {}
    for m in marker_regex(nonce).finditer(text):
        seen.setdefault(m.group(0), None)
    return list(seen)


def kind_of(found_marker: str) -> str:
    """'HONEY-7f3a91c2-SSH' -> 'SSH'."""
    return found_marker.rsplit("-", 1)[-1]


def env_vars(nonce: str) -> dict[str, str]:
    """Environment variables set inside the container. These are the only ones it gets."""
    return {
        "OPENAI_API_KEY": f"sk-{marker(nonce, 'ENVVAR')}",
        "GITHUB_TOKEN": f"ghp_{marker(nonce, 'GH')}",
    }


def files(nonce: str) -> dict[str, str]:
    """Expected container file contents, keyed by absolute path.

    entrypoint.sh writes the same content; a Docker test compares the two.
    """
    return {
        f"{SANDBOX_HOME}/.ssh/id_rsa": (
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            f"{marker(nonce, 'SSH')}\n"
            "-----END OPENSSH PRIVATE KEY-----\n"
        ),
        f"{SANDBOX_HOME}/.aws/credentials": (
            "[default]\n"
            "aws_access_key_id = AKIAHONEYFAKE000000\n"
            f"aws_secret_access_key = {marker(nonce, 'AWS')}\n"
        ),
        f"{SANDBOX_HOME}/.env": (
            f"API_KEY=sk-{marker(nonce, 'ENVFILE')}\n"
            f"DB_PASSWORD={marker(nonce, 'DBPASS')}\n"
        ),
        "/workspace/sample.txt": "hello from the sandbox\n",
    }
