from enum import Enum

from pydantic import BaseModel


class Severity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Confidence(str, Enum):
    confirmed = "confirmed"  # backed by a logged fact (honeytoken, syscall, snapshot diff, marker echo)
    pattern_match = "pattern_match"  # a static pattern matched; not proven at runtime
    heuristic = "heuristic"  # rule of thumb (for example, a risky parameter name)
    llm_opinion = "llm_opinion"  # model judgment; severity capped at medium


class Category(str, Enum):
    tool_poisoning = "tool_poisoning"
    data_exfiltration = "data_exfiltration"
    permissions = "permissions"
    network = "network"
    shadowing = "shadowing"
    prompt_safety = "prompt_safety"
    resource_safety = "resource_safety"
    integrity = "integrity"  # rug pull, changing tool lists
    input_handling = "input_handling"
    output_injection = "output_injection"
    metadata = "metadata"


class Evidence(BaseModel):
    kind: str  # "text" | "tool_call" | "syscall" | "diff" | "snapshot"
    summary: str  # one line for humans
    detail: str  # excerpt, max 2000 chars
    tool: str | None = None
    arguments: dict | None = None
    matched: str | None = None  # honeytoken marker, regex, or syscall path


class Finding(BaseModel):
    id: str  # "<rule_id>:<target>", for example "TP-001:get_weather"
    rule_id: str
    title: str
    category: Category
    severity: Severity
    confidence: Confidence
    target: str  # tool, prompt, or resource name, or "server"
    phase: str  # "static" | "dynamic"
    description: str
    impact: str
    remediation: str
    evidence: list[Evidence]


class ToolSnapshot(BaseModel):
    taken_at: str
    label: str  # "initial" | "after_probes" | "after_delay"
    tools: dict[str, str]  # tool name -> sha256 of (name, description, inputSchema)
    raw: dict[str, dict]  # tool name -> full tool definition, for diffs


class ServerSurface(BaseModel):
    server_name: str
    server_version: str | None = None
    tools: list[dict]
    prompts: list[dict]
    resources: list[dict]
    resource_templates: list[dict]
    resource_contents: dict[str, str]  # uri -> text, truncated to 20,000 chars each


class ScanResult(BaseModel):
    meta: dict  # target, nonce, started, duration_s, tool_calls_made
    coverage: dict  # what ran and what did not apply (section 10.3)
    findings: list[Finding]
    trust_score: int  # 0 to 100
    verdict: str  # "do_not_use" | "use_with_caution" | "no_issues_found"
    capabilities: list[str]  # detected: filesystem, network, shell, database, secrets
