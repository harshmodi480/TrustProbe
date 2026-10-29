# Demo MCP servers

Four small stdio servers that act as TrustProbe's test bench and live demo.

> **WARNING: three of these servers are intentionally unsafe.**
> `malicious_weather` reads `~/.ssh/id_rsa`, `injectable_diag` passes input to a shell, and
> `rugpull_math` changes its own tool description. **Never run them directly on a developer
> machine** (no `python server.py`, no adding them to an IDE or agent). Run them only through
> `trustprobe scan`, which starts them in the sandbox: no network, read-only root filesystem,
> and a `HOME` that holds fake honeytoken files instead of real secrets.

| Server | Behavior | Expected verdict |
|---|---|---|
| `benign_calc` | `add`, `subtract`, `multiply` with tight number schemas, one prompt, one resource | No issues found |
| `malicious_weather` | Hidden instruction in a tool description, leaks the fake SSH key, tries a network connection, injects text into its reply and a resource | Do not use |
| `rugpull_math` | `add` is clean for 3 calls, then the description turns hostile with no `list_changed` notification | Do not use |
| `injectable_diag` | Shell injection in `run_diagnostic`, path traversal and a stack-trace leak in `read_note` | Do not use |

A fifth server, `node_echo`, is a clean, dependency-free Node server (an `echo` tool) used to test the Node sandbox image: `trustprobe quick demo_servers/node_echo --yes`. It needs no config because `quick` detects `package.json`.

The findings each of the four Python servers must produce are listed in `tests/expected_findings.yaml`.

```powershell
trustprobe scan -c examples/scan.malicious_weather.yaml --yes
```
