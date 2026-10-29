# Application Name
TrustProbe

## Description
TrustProbe is a security scanning tool for MCP (Model Context Protocol) servers. It runs each server inside a locked-down Docker sandbox, plants honeytokens (fake secrets), executes the server's tools with both safe and adversarial inputs, and produces a detailed security report with evidence, a trust score, and a verdict.

The web interface lets you register MCP servers, configure scan options, stream live output, and review findings — all from a browser.

## Purpose
AI agents rely on MCP servers to access tools and data. A malicious or poorly written MCP server can leak secrets, read arbitrary files, make unexpected network calls, or behave differently once deployed (rug-pull). TrustProbe exposes these risks before an MCP server is connected to a production AI system, giving teams an auditable security baseline for every server they consume or ship.

---

## Quick Start

### With Docker Compose (recommended)

```bash
docker compose up --build
```

Open **http://localhost:8000** in your browser.

### Without Docker Compose

```bash
docker build -t trustprobe .
docker run -p 8000:8000 -v /var/run/docker.sock:/var/run/docker.sock trustprobe
```

Open **http://localhost:8000** in your browser.

---

> **Note:** TrustProbe requires access to the host Docker daemon (mounted via `/var/run/docker.sock`) to sandbox the MCP servers it scans. Ensure Docker is running on the host before starting the container.
