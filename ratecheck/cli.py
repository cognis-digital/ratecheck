"""RATECHECK command-line interface.

Usage::

    python -m ratecheck check demos/01-basic/login_burst.json
    python -m ratecheck check spec.json --format json
    python -m ratecheck --version

Exit codes:
    0  no actionable findings (clean / info only)
    1  one or more actionable findings (severity >= low)
    2  usage / input error
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import Report, analyze_spec, load_spec

_SEV_LABEL = {
    "info": "INFO",
    "low": "LOW",
    "medium": "MED",
    "high": "HIGH",
    "critical": "CRIT",
}


def _render_table(report: Report) -> str:
    lines: List[str] = []
    s = report.summary
    lines.append(f"{TOOL_NAME} {TOOL_VERSION}")
    lines.append(f"Target : {report.method} {report.target}")
    lines.append(
        "Probes : {total} total | {ok} accepted | {th} throttled | {err} 5xx".format(
            total=s["total_probes"],
            ok=s["accepted_2xx"],
            th=s["throttled_429_503"],
            err=s["server_errors_5xx"],
        )
    )
    rps = s.get("effective_rps")
    lines.append(
        "Rate   : {rps} req/s over {win}s | headers: {hdr}".format(
            rps=(rps if rps is not None else "n/a"),
            win=s["window_seconds"],
            hdr=("yes" if s["ratelimit_headers_present"] else "NONE"),
        )
    )
    lines.append(f"Verdict: max severity = {report.max_severity.upper()}")
    lines.append("")
    if not report.findings:
        lines.append("No findings.")
        return "\n".join(lines)

    lines.append("Findings:")
    for f in report.findings:
        lines.append(f"  [{_SEV_LABEL[f.severity]:<4}] {f.code}  {f.title}")
        lines.append(f"         {f.detail}")
    return "\n".join(lines)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=(
            "Probe an API endpoint's rate-limit / abuse-resistance posture from a "
            "supplied probe trace (defensive / authorized-testing use only)."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{TOOL_NAME} {TOOL_VERSION}",
    )
    sub = parser.add_subparsers(dest="command")

    check = sub.add_parser(
        "check",
        help="Analyze a request/probe spec file for rate-limit weaknesses.",
    )
    check.add_argument("spec", help="Path to the JSON spec file.")
    check.add_argument(
        "--format",
        choices=("table", "json"),
        default="table",
        help="Output format (default: table).",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help(sys.stderr)
        return 2

    if args.command != "check":
        parser.print_help(sys.stderr)
        return 2

    try:
        spec = load_spec(args.spec)
    except FileNotFoundError:
        print(f"error: spec file not found: {args.spec}", file=sys.stderr)
        return 2
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"error: invalid spec: {exc}", file=sys.stderr)
        return 2

    try:
        report = analyze_spec(spec, tool=TOOL_NAME, version=TOOL_VERSION)
    except Exception as exc:  # pragma: no cover
        print(f"error: analysis failed unexpectedly: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(_render_table(report))

    return 1 if report.actionable else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
