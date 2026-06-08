"""RATECHECK — API rate-limit / abuse-resistance triage (defensive, authorized-testing only).

Standard-library only. Analyzes a request spec (target + an OBSERVED probe trace
or a captured set of responses) to detect whether the endpoint enforces rate
limiting, exposes standard rate-limit headers, and degrades gracefully under
burst load. This is a *detection / triage* tool: it does not generate attack
traffic on its own — it consumes a probe trace you (an authorized tester) supply.
"""

from .core import (
    Probe,
    Spec,
    Finding,
    Report,
    analyze_spec,
    load_spec,
    SEVERITIES,
)

TOOL_NAME = "ratecheck"
TOOL_VERSION = "1.0.0"

__all__ = [
    "Probe",
    "Spec",
    "Finding",
    "Report",
    "analyze_spec",
    "load_spec",
    "SEVERITIES",
    "TOOL_NAME",
    "TOOL_VERSION",
]
