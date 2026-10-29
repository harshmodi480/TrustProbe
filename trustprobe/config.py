"""Scan configuration: parse and validate scan.yaml into typed models."""

from __future__ import annotations

import json
import secrets
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, ValidationError, field_validator

from trustprobe.models import Severity

CAPABILITIES = ("filesystem", "network", "shell", "database", "secrets")


class ConfigError(Exception):
    """A config problem, phrased so the operator knows which field to fix."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SourceConfig(_Strict):
    type: Literal["path", "npm", "pypi"]
    path: str | None = None
    package: str | None = None
    version: str | None = None

    def check(self) -> None:
        if self.type == "path" and not self.path:
            raise ValueError("source.path is required when source.type is 'path'")
        if self.type in ("npm", "pypi") and not self.package:
            raise ValueError(f"source.package is required when source.type is '{self.type}'")


class InstallConfig(_Strict):
    requirements: str | None = None  # python: requirements file inside the server dir
    package_json: bool | None = None  # node: run npm install from package.json
    package: str | None = None  # npm/pypi: package name
    version: str | None = None  # npm/pypi: pinned version


class ServerConfig(_Strict):
    source: SourceConfig
    runtime: Literal["python", "node"] | None = None
    install: InstallConfig = Field(default_factory=InstallConfig)
    command: list[str]
    startup_timeout_s: int = Field(default=30, gt=0)
    declared_capabilities: list[str] = Field(default_factory=list)

    @field_validator("command", mode="before")
    @classmethod
    def _command_is_list(cls, v):
        if isinstance(v, str):
            raise ValueError("must be a list of strings, not a shell string")
        return v

    @field_validator("command")
    @classmethod
    def _command_not_empty(cls, v: list[str]):
        if not v:
            raise ValueError("must not be empty")
        return v

    @field_validator("declared_capabilities")
    @classmethod
    def _known_capabilities(cls, v: list[str]):
        bad = [c for c in v if c not in CAPABILITIES]
        if bad:
            raise ValueError(f"unknown capabilities {bad}; allowed: {list(CAPABILITIES)}")
        return v


class StaticConfig(_Strict):
    llm_review: bool = False


class DynamicConfig(_Strict):
    enabled: bool = True
    call_timeout_s: int = Field(default=20, gt=0)
    max_calls_per_tool: int = Field(default=12, gt=0)
    max_total_calls: int = Field(default=200, gt=0)
    rugpull_delay_s: int = Field(default=10, ge=0)


class ScanSection(_Strict):
    mode: Literal["static", "full"] = "full"
    total_timeout_s: int = Field(default=180, gt=0)
    static: StaticConfig = Field(default_factory=StaticConfig)
    dynamic: DynamicConfig = Field(default_factory=DynamicConfig)


class PolicyConfig(_Strict):
    do_not_use_on: list[Severity] = Field(default_factory=lambda: [Severity.critical])
    allow_network: bool = False


class LLMConfig(_Strict):
    enabled: bool = False
    provider_env: str = "TRUSTPROBE_LLM_API_KEY"  # name of the environment variable that holds the API key
    model: str = "claude-opus-5-5"


class ScanConfig(_Strict):
    name: str
    server: ServerConfig
    scan: ScanSection = Field(default_factory=ScanSection)
    policy: PolicyConfig = Field(default_factory=PolicyConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    out_dir: str = "out/"

    # Filled by parse_config, not part of the YAML.
    _config_dir: Path = PrivateAttr(default=Path("."))

    @property
    def config_dir(self) -> Path:
        return self._config_dir

    @property
    def source_path(self) -> Path | None:
        """Absolute path of the server directory, for `path` sources."""
        if self.server.source.type != "path" or not self.server.source.path:
            return None
        return (self._config_dir / self.server.source.path).resolve()

    @property
    def out_path(self) -> Path:
        out = Path(self.out_dir)
        return out if out.is_absolute() else (self._config_dir / out).resolve()

    @property
    def runtime(self) -> str:
        """Configured runtime, or auto-detected from the source directory."""
        if self.server.runtime:
            return self.server.runtime
        src = self.source_path
        if src is not None and (src / "package.json").exists():
            return "node"
        if self.server.source.type == "npm":
            return "node"
        return "python"


def _format_errors(err: ValidationError) -> str:
    lines = []
    for e in err.errors():
        loc = ".".join(str(p) for p in e["loc"]) or "<root>"
        lines.append(f"{loc}: {e['msg']}")
    return "; ".join(lines)


def parse_config(data: dict, config_dir: Path) -> ScanConfig:
    """Validate a raw dict and check that referenced paths exist."""
    if not isinstance(data, dict):
        raise ConfigError("config must be a YAML mapping at the top level")
    try:
        cfg = ScanConfig.model_validate(data)
        cfg.server.source.check()
    except ValidationError as e:
        raise ConfigError(_format_errors(e)) from e
    except ValueError as e:
        raise ConfigError(f"server.source: {e}") from e

    cfg._config_dir = config_dir
    src = cfg.source_path
    if src is not None:
        if not src.exists():
            raise ConfigError(f"server.source.path: '{cfg.server.source.path}' does not exist (resolved relative to the config file)")
        if not src.is_dir():
            raise ConfigError(f"server.source.path: '{cfg.server.source.path}' is not a directory")
        req = cfg.server.install.requirements
        if req and not (src / req).exists():
            raise ConfigError(f"server.install.requirements: '{req}' not found in the server directory")
    if cfg.scan.static.llm_review and not cfg.llm.enabled:
        raise ConfigError("scan.static.llm_review: requires llm.enabled to be true")
    return cfg


def load_config(path: str | Path) -> ScanConfig:
    """Load and validate scan.yaml. Raises ConfigError with a fix-oriented message."""
    p = Path(path)
    if not p.is_file():
        raise ConfigError(f"config file not found: {p}")
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise ConfigError(f"invalid YAML in {p.name}: {e}") from e
    return parse_config(data, p.resolve().parent)


def new_nonce() -> str:
    """8 hex characters, generated once per scan."""
    return secrets.token_hex(4)


def save_run_state(out_dir: Path, nonce: str) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    p = out_dir / "run_state.json"
    p.write_text(json.dumps({"nonce": nonce}), encoding="utf-8")
    return p
