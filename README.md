# TrustProbe

TrustProbe is a security scanning tool for MCP (Model Context Protocol) servers. It runs each server inside a locked-down Docker sandbox, plants honeytokens (fake secrets), executes the server's tools with both safe and adversarial inputs, and produces a detailed security report with evidence, a trust score, and a verdict.

The web interface lets you register MCP servers, configure scan options, stream live output, and review findings — all from a browser.

## Why it exists

AI agents rely on MCP servers to access tools and data. A malicious or poorly written MCP server can leak secrets, read arbitrary files, make unexpected network calls, or behave differently once deployed (rug-pull). TrustProbe exposes these risks before an MCP server is connected to a production AI system, giving teams an auditable security baseline for every server they consume or ship.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| **Python 3.11+** | Required to run TrustProbe and the web app |
| **Node.js + npm/npx** | Required to scan `npm:` MCP servers |
| **Docker Desktop** | Required for **Full** scans only. Not needed for **Static** scans. |

Install Python from [python.org](https://python.org) and Node.js from [nodejs.org](https://nodejs.org). Docker Desktop is available at [docker.com](https://docker.com).

---

## Running the Web App

The web app is the easiest way to use TrustProbe. It provides a browser UI for registering servers, running scans, and viewing results.

**Step 1 — start the server:**

```bash
python run.py
```

On first run this automatically creates a virtual environment and installs all dependencies. Subsequent runs skip setup and start immediately.

**Step 2 — open the browser:**

```
http://localhost:7860
```

That's it. Add an MCP server in the UI, choose a scan mode, and click **Run Scan**.

> If port 7860 is already in use, start on a different port:
> ```bash
> python run.py --port 8080
> ```

---

## Scan Modes

TrustProbe has two scan modes selectable in the UI and CLI.

### Static

Connects to the MCP server, reads everything it advertises (tool names, descriptions, input schemas, resources, prompts), and applies pattern-matching and heuristic rules against those descriptions — **without calling any tool**.

**What it catches:**
- Tool poisoning text hidden in descriptions (e.g. instructions to leak secrets)
- Suspicious permission patterns (broad file access, shell execution)
- Shadowing attempts (tools that override well-known tool names)
- Dangerous or misleading tool descriptions
- Metadata issues

**What it misses:**
- Actual runtime behavior — a tool description can look clean while the implementation exfiltrates data

**Docker required:** No. Static mode runs the server directly on the host to enumerate its surface, then applies rules locally. Works without Docker Desktop.

**Speed:** Fast — typically completes in seconds.

---

### Full

Does everything Static does, then **calls every tool** inside a hardened Docker sandbox and observes real runtime behavior via syscall tracing and network monitoring.

**What it catches (in addition to all Static findings):**
- Actual outbound network requests made during tool execution (DY-003)
- Real file system access outside expected boundaries (DY-007/DY-008)
- Data exfiltration — honeytoken values sent to external endpoints (DY-001/DY-002)
- Command injection via crafted inputs (DY-006)
- Output injection — malicious content injected into tool responses (DY-005)
- Rug-pull — tools that change their behavior or schema between calls (DY-004)
- Large or unexpected outputs (DY-010)

**Docker required:** Yes. The sandbox enforces `--network none` after enumeration, a read-only root filesystem, no Linux capabilities, a non-root user, memory and CPU limits, and fake secrets (honeytokens) — so every tool call is safe to execute and fully observable.

**Speed:** Slower — depends on the number of tools and their startup time. Typically 1–5 minutes.

---

### Which mode should I use?

| Situation | Recommended mode |
|---|---|
| Quick check, Docker not available | Static |
| First look at an unfamiliar server | Static |
| Pre-deployment security gate | Full |
| Investigating a suspicious server | Full |
| CI pipeline | Full (with Docker) or Static (without) |

Static is a useful first pass. Full is the authoritative check. When in doubt, run Full.

---

## CLI Usage

TrustProbe also has a full CLI for scripting and CI use.

```bash
# Quick static scan of an npm package (no Docker needed)
python run.py quick npm:@modelcontextprotocol/server-github --static-only --yes

# Quick full scan (Docker required)
python run.py quick npm:@playwright/mcp --yes

# Scan using a config file
python run.py scan -c scan.yaml

# List all rules and probes
python run.py rules list

# Re-render a report from existing results
python run.py report out/quick-server-github/results.json
```

---

## Adding a Custom MCP Server for Testing

You can write your own MCP server and scan it with TrustProbe using the **Local Path** source type. This is useful for testing servers you are building before connecting them to an AI agent.

### Python server

**Minimum structure:**

```
my_server/
├── server.py
└── requirements.txt   ← optional, only if you need packages beyond mcp
```

**`server.py` template:**

```python
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("my-server")

@mcp.tool()
def hello(name: str) -> str:
    """Say hello."""
    return f"Hello, {name}!"

if __name__ == "__main__":
    mcp.run()
```

**`requirements.txt`** (only needed for extra packages):

```
mcp==1.30.0
requests>=2.31
```

> After adding a `requirements.txt`, re-run `python run.py` once to install the dependencies into the shared venv before scanning.

### Node.js server

**Minimum structure:**

```
my_server/
├── server.js
└── package.json
```

**`package.json`** must include a `main` or `bin` entry pointing to your entrypoint:

```json
{
  "name": "my-server",
  "version": "1.0.0",
  "main": "server.js"
}
```

### How to scan it

**Via the web UI:**

1. Click **Add Server**
2. Set Source Type to **Local Path**
3. Click **Browse** (or type the absolute path to your server directory)
4. Choose **Static** or **Full** scan mode and click **Run Scan**

**Via the CLI:**

```bash
python run.py quick path/to/my_server --static-only --yes
```

### Rules for writing a server

| Rule | Reason |
|---|---|
| Server must speak MCP over **stdio** | TrustProbe connects via stdin/stdout |
| Entry point must be `server.py`, `main.py`, `app.py`, or `__main__.py` (Python) | Auto-detected by `quick` |
| Entry point must be in `package.json` `main` or `bin` (Node) | Auto-detected by `quick` |
| Call `mcp.run()` at the end (Python) | Required to start the stdio transport |
| Do not require interactive input on startup | TrustProbe cannot respond to prompts |

### Existing demo servers

The `demo_servers/` directory contains four ready-made servers for reference and testing:

| Server | What it does | Expected verdict |
|---|---|---|
| `benign_calc` | Safe calculator — add, subtract, multiply | No issues |
| `malicious_weather` | Tool poisoning, SSH key leak, network egress | Do not use |
| `injectable_diag` | Shell injection, path traversal | Do not use |
| `rugpull_math` | Changes tool description after 3 calls | Do not use |

> **Warning:** The three unsafe servers are intentionally malicious. Never run them directly — only through TrustProbe, which sandboxes them.

---

## Docker Compose (alternative)

To run TrustProbe entirely inside Docker (web app + scanner containerised):

```bash
docker compose up --build
```

Open **http://localhost:8000** in your browser.

> This mounts the host Docker socket (`/var/run/docker.sock`) so the container can sandbox MCP servers. Docker must be running on the host.
