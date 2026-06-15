"""RATECHECK MCP server — exposes analyze() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
import json
import sys
from ratecheck.core import load_spec, analyze_spec


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-ratecheck[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print(
            "Install the MCP extra: pip install 'cognis-ratecheck[mcp]'",
            file=sys.stderr,
        )
        return 1
    app = FastMCP("ratecheck")

    @app.tool()
    def ratecheck_scan(spec_path: str) -> str:
        """Probe API rate-limit/abuse resistance from a request spec file.

        Args:
            spec_path: Path to a JSON probe-trace spec file.

        Returns:
            JSON string with findings and summary.
        """
        try:
            spec = load_spec(spec_path)
        except FileNotFoundError:
            return json.dumps({"error": f"spec file not found: {spec_path}"})
        except ValueError as exc:
            return json.dumps({"error": f"invalid spec: {exc}"})
        report = analyze_spec(spec)
        return json.dumps(report.to_dict(), indent=2)

    app.run()
    return 0
