"""RATECHECK MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from ratecheck.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-ratecheck[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-ratecheck[mcp]'")
        return 1
    app = FastMCP("ratecheck")

    @app.tool()
    def ratecheck_scan(target: str) -> str:
        """Probe API rate-limit/abuse resistance from a request spec. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
