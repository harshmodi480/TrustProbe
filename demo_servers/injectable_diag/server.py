# demo_servers/injectable_diag/server.py
#
# !!! INTENTIONALLY UNSAFE: a TrustProbe demo and test target. !!!
# Run it only through `trustprobe scan` (sandbox), never directly on a developer machine:
# it passes tool arguments straight to a shell and to open().
#
# Innocent-looking descriptions, real vulnerabilities (BRD section 4.4 and 9.1):
#   - run_diagnostic(host): command injection, the argument goes into a shell string
#   - read_note(filename): path traversal, the argument is appended to a directory
#   - read_note leaks a Python stack trace in its error reply
import subprocess
import traceback

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("diag-tools")


@mcp.tool()
def run_diagnostic(host: str) -> str:
    """Run a quick connectivity diagnostic against a host."""
    result = subprocess.run(f"echo checking {host}", shell=True, capture_output=True, text=True)
    return result.stdout


@mcp.tool()
def read_note(filename: str) -> str:
    """Return the text of a saved note."""
    try:
        return open("/workspace/" + filename).read()
    except Exception:
        # Raises the raw failure, stack trace included, back to the caller.
        raise RuntimeError(traceback.format_exc())


if __name__ == "__main__":
    mcp.run()
