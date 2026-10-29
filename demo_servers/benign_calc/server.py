# demo_servers/benign_calc/server.py  (safe on purpose)
#
# A clean calculator server used as the negative control for TrustProbe:
# tight number schemas, plain descriptions, no file, network, or process access.
from typing import Annotated

from mcp.server.fastmcp import FastMCP
from pydantic import Field

mcp = FastMCP("benign-calc")

Num = Annotated[float, Field(ge=-1e9, le=1e9)]


@mcp.tool()
def add(a: Num, b: Num) -> float:
    """Add two numbers."""
    return a + b


@mcp.tool()
def subtract(a: Num, b: Num) -> float:
    """Subtract the second number from the first."""
    return a - b


@mcp.tool()
def multiply(a: Num, b: Num) -> float:
    """Multiply two numbers."""
    return a * b


@mcp.prompt()
def explain_result(value: str) -> str:
    """Ask for a plain-language explanation of a calculation result."""
    return f"Explain in one short sentence what the number {value} means as the result of a calculation."


@mcp.resource("calc://help")
def help_text() -> str:
    """Basic calculator help."""
    return "This server adds, subtracts and multiplies numbers."


if __name__ == "__main__":
    mcp.run()
