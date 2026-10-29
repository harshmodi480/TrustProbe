"""MCP client wrapper. Every call into the `mcp` SDK lives in this module.

Written against mcp 1.30.0 (pinned in pyproject.toml). It connects over stdio to the
`docker run -i` process, enumerates what the server advertises, calls tools, and stamps
every call with epoch start/end times so syscall events can be attributed to it.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import anyio
from mcp import types
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, get_default_environment, stdio_client
from mcp.shared.exceptions import McpError

from trustprobe.models import ServerSurface, ToolSnapshot

RESOURCE_TEXT_LIMIT = 20_000
MAX_PAGES = 50
# Host variables the docker CLI itself may need (these configure the CLI, they are never
# passed into the container).
_DOCKER_CLI_ENV = ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH")


class ClientError(Exception):
    """The server could not be reached or did not complete the MCP handshake."""


@dataclass
class CallRecord:
    kind: str  # "tool" | "prompt" | "resource"
    name: str
    arguments: dict | None
    start: float  # epoch seconds, comparable with strace -ttt timestamps
    end: float
    text: str = ""  # human-readable output
    structured: str = ""  # JSON of structuredContent, if the server sent any
    parts: list[str] = field(default_factory=list)  # prompt messages
    is_error: bool = False
    error: str | None = None
    timed_out: bool = False
    connection_lost: bool = False

    @property
    def scan_text(self) -> str:
        """Everything the server returned, for marker and pattern scans."""
        return f"{self.text}\n{self.structured}" if self.structured else self.text


def tool_fingerprint(tool: dict) -> str:
    """sha256 of (name, description, inputSchema)."""
    payload = {
        "name": tool.get("name", ""),
        "description": tool.get("description") or "",
        "inputSchema": tool.get("inputSchema") or {},
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()


def make_snapshot(label: str, tools: list[dict]) -> ToolSnapshot:
    return ToolSnapshot(
        taken_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        label=label,
        tools={t["name"]: tool_fingerprint(t) for t in tools},
        raw={t["name"]: t for t in tools},
    )


def _dump(model: Any) -> dict:
    return model.model_dump(mode="json", by_alias=True, exclude_none=True)


def _content_text(content: list[Any]) -> str:
    out = []
    for item in content:
        if isinstance(item, types.TextContent):
            out.append(item.text)
        elif isinstance(item, types.EmbeddedResource):
            res = item.resource
            out.append(res.text if isinstance(res, types.TextResourceContents) else f"[binary resource {res.uri}]")
        else:
            out.append(f"[{getattr(item, 'type', 'content')}]")
    return "\n".join(out)


def _docker_cli_env() -> dict[str, str]:
    env = dict(get_default_environment())
    for key in _DOCKER_CLI_ENV:
        if key in os.environ:
            env[key] = os.environ[key]
    return env


class McpClient:
    """Async context manager: `async with McpClient(...) as client:`."""

    def __init__(
        self,
        command: str,
        args: list[str],
        *,
        startup_timeout_s: float = 30,
        call_timeout_s: float = 20,
        stderr_log: Path | None = None,
    ):
        self._params = StdioServerParameters(command=command, args=args, env=_docker_cli_env())
        self.startup_timeout_s = startup_timeout_s
        self.call_timeout_s = call_timeout_s
        self.stderr_log = stderr_log
        self._stack = AsyncExitStack()
        self.session: ClientSession | None = None

        self.server_name = "unknown"
        self.server_version: str | None = None
        self.capabilities: dict = {}
        self.list_changed_seen = False
        self.list_changed_times: list[float] = []
        self.calls: list[CallRecord] = []
        self.first_response_at: float | None = None

    # ---- lifecycle

    async def __aenter__(self) -> "McpClient":
        try:
            if self.stderr_log is not None:
                self.stderr_log.parent.mkdir(parents=True, exist_ok=True)
                errlog = self._stack.enter_context(open(self.stderr_log, "w", encoding="utf-8"))
                read, write = await self._stack.enter_async_context(stdio_client(self._params, errlog=errlog))
            else:
                read, write = await self._stack.enter_async_context(stdio_client(self._params))
            self.session = await self._stack.enter_async_context(
                ClientSession(read, write, message_handler=self._on_message)
            )
            try:
                with anyio.fail_after(self.startup_timeout_s):
                    init = await self.session.initialize()
            except TimeoutError:
                raise ClientError(f"server did not complete the MCP handshake within {self.startup_timeout_s}s") from None
            self.first_response_at = time.time()
            self.server_name = init.serverInfo.name
            self.server_version = init.serverInfo.version
            self.capabilities = _dump(init.capabilities)
        except BaseException as exc:
            await self._stack.aclose()
            if isinstance(exc, Exception) and not isinstance(exc, ClientError):
                raise ClientError(f"could not connect to the server: {exc}") from exc
            raise
        return self

    async def __aexit__(self, exc_type, exc, tb) -> bool | None:
        return await self._stack.__aexit__(exc_type, exc, tb)

    async def _on_message(self, message: Any) -> None:
        if isinstance(message, types.ServerNotification) and isinstance(message.root, types.ToolListChangedNotification):
            self.list_changed_seen = True
            self.list_changed_times.append(time.time())

    # ---- listing

    async def _paged(self, method: str, attr: str) -> list[dict]:
        assert self.session is not None
        items: list[dict] = []
        cursor: str | None = None
        for _ in range(MAX_PAGES):
            try:
                with anyio.fail_after(self.call_timeout_s):
                    result = await getattr(self.session, method)(cursor)
            except McpError:  # the server does not implement this method
                return items
            items += [_dump(i) for i in getattr(result, attr)]
            cursor = result.nextCursor
            if not cursor:
                break
        return items

    async def list_tools(self) -> list[dict]:
        return await self._paged("list_tools", "tools")

    async def list_prompts(self) -> list[dict]:
        return await self._paged("list_prompts", "prompts")

    async def list_resources(self) -> list[dict]:
        return await self._paged("list_resources", "resources")

    async def list_resource_templates(self) -> list[dict]:
        return await self._paged("list_resource_templates", "resourceTemplates")

    async def snapshot(self, label: str) -> ToolSnapshot:
        return make_snapshot(label, await self.list_tools())

    # ---- calls

    async def _timed(self, rec: CallRecord, coro_factory) -> CallRecord:
        try:
            with anyio.fail_after(self.call_timeout_s):
                await coro_factory(rec)
        except TimeoutError:
            rec.timed_out, rec.error = True, f"timed out after {self.call_timeout_s}s"
        except McpError as e:
            rec.is_error, rec.error = True, e.error.message
            rec.text = rec.text or e.error.message
        except (anyio.ClosedResourceError, anyio.BrokenResourceError, anyio.EndOfStream) as e:
            rec.connection_lost, rec.error = True, f"connection to the server was lost ({type(e).__name__})"
        finally:
            rec.end = time.time()
            self.calls.append(rec)
        return rec

    async def call_tool(self, name: str, arguments: dict | None = None) -> CallRecord:
        assert self.session is not None
        rec = CallRecord("tool", name, arguments, time.time(), time.time())

        async def go(r: CallRecord) -> None:
            res = await self.session.call_tool(name, arguments or {})
            r.text = _content_text(res.content)
            r.is_error = bool(res.isError)
            if res.structuredContent is not None:
                r.structured = json.dumps(res.structuredContent, ensure_ascii=False)

        return await self._timed(rec, go)

    async def get_prompt(self, name: str, arguments: dict[str, str] | None = None) -> CallRecord:
        assert self.session is not None
        rec = CallRecord("prompt", name, arguments, time.time(), time.time())

        async def go(r: CallRecord) -> None:
            res = await self.session.get_prompt(name, arguments)
            r.parts = [_content_text([m.content]) for m in res.messages]
            r.text = "\n".join(r.parts)

        return await self._timed(rec, go)

    async def read_resource(self, uri: str) -> CallRecord:
        assert self.session is not None
        rec = CallRecord("resource", uri, None, time.time(), time.time())

        async def go(r: CallRecord) -> None:
            res = await self.session.read_resource(uri)  # type: ignore[arg-type]  # SDK accepts a str that parses as AnyUrl
            parts = []
            for c in res.contents:
                if isinstance(c, types.TextResourceContents):
                    parts.append(c.text)
                else:
                    parts.append(f"[binary content, {len(c.blob)} base64 chars]")
            r.parts = parts
            r.text = "\n".join(parts)

        return await self._timed(rec, go)

    # ---- enumeration

    async def enumerate_surface(self) -> ServerSurface:
        """List tools, prompts, resources and templates; fetch prompts and read resources.

        No tool is called. Prompts are fetched with every argument set to "test".
        """
        tools = await self.list_tools()
        prompts = await self.list_prompts()
        for p in prompts:
            args = {a["name"]: "test" for a in (p.get("arguments") or [])}
            rec = await self.get_prompt(p["name"], args)
            p["messages"] = rec.parts
        resources = await self.list_resources()
        templates = await self.list_resource_templates()
        contents: dict[str, str] = {}
        for r in resources:
            rec = await self.read_resource(r["uri"])
            contents[r["uri"]] = rec.text[:RESOURCE_TEXT_LIMIT]
        return ServerSurface(
            server_name=self.server_name,
            server_version=self.server_version,
            tools=tools,
            prompts=prompts,
            resources=resources,
            resource_templates=templates,
            resource_contents=contents,
        )
