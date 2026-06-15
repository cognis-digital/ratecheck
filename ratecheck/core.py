"""RATECHECK core engine.

Consumes a *probe trace* — a record of responses an authorized tester observed
when sending a controlled burst of requests at an endpoint — and evaluates the
endpoint's rate-limit / abuse-resistance posture. No traffic is generated here;
this module only performs detection and triage over supplied evidence.

Spec schema (JSON)::

    {
      "target": "https://api.example.com/v1/login",
      "method": "POST",
      "window_seconds": 10,          # observation window the probes span
      "expected_limit": 20,          # OPTIONAL: documented per-window limit
      "auth_required": true,         # OPTIONAL: endpoint is sensitive (login/etc.)
      "probes": [
        {"t": 0.00, "status": 200, "headers": {"X-RateLimit-Remaining": "19"}},
        {"t": 0.01, "status": 200, "headers": {"X-RateLimit-Remaining": "18"}},
        ...
        {"t": 0.40, "status": 429, "headers": {"Retry-After": "5"}}
      ]
    }

Each probe is one observed response. ``t`` is seconds since the burst started.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple

SEVERITIES = ("info", "low", "medium", "high", "critical")
_SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

# Headers that, when present, signal the server communicates limits to clients.
_RATELIMIT_HEADER_HINTS = (
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
    "ratelimit-limit",
    "ratelimit-remaining",
    "ratelimit-reset",
    "x-rate-limit-limit",
    "retry-after",
)

# Status codes that indicate the server actively throttled a request.
_THROTTLE_STATUSES = (429, 503)


@dataclass
class Probe:
    """One observed response in a probe trace."""

    t: float
    status: int
    headers: Dict[str, str] = field(default_factory=dict)

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Probe":
        if not isinstance(d, dict):
            raise ValueError(f"each probe must be a JSON object, got {type(d).__name__}")
        if "status" not in d:
            raise ValueError("probe missing required field 'status'")
        try:
            t_val = float(d.get("t", 0.0))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"probe 't' must be a number: {exc}") from exc
        try:
            status_val = int(d["status"])
        except (TypeError, ValueError) as exc:
            raise ValueError(f"probe 'status' must be an integer: {exc}") from exc
        if not (100 <= status_val <= 599):
            raise ValueError(
                f"probe 'status' {status_val} is not a valid HTTP status code (100-599)"
            )
        raw_headers = d.get("headers", {}) or {}
        if not isinstance(raw_headers, dict):
            raise ValueError("probe 'headers' must be a JSON object")
        # Normalize header keys to lowercase for case-insensitive lookups.
        headers = {str(k).lower(): str(v) for k, v in raw_headers.items()}
        return Probe(
            t=t_val,
            status=status_val,
            headers=headers,
        )


@dataclass
class Spec:
    """A parsed request/probe specification."""

    target: str
    method: str = "GET"
    window_seconds: float = 0.0
    expected_limit: Optional[int] = None
    auth_required: bool = False
    probes: List[Probe] = field(default_factory=list)

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Spec":
        if not isinstance(d, dict):
            raise ValueError(f"spec must be a JSON object, got {type(d).__name__}")
        if "target" not in d:
            raise ValueError("spec missing required field 'target'")
        target = str(d["target"]).strip()
        if not target:
            raise ValueError("spec 'target' must not be empty")
        probes_raw = d.get("probes", []) or []
        if not isinstance(probes_raw, list):
            raise ValueError("'probes' must be a list")
        probes = [Probe.from_dict(p) for p in probes_raw]
        win_raw = d.get("window_seconds")
        if win_raw is not None:
            try:
                win = float(win_raw)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"'window_seconds' must be a number: {exc}") from exc
            if win < 0:
                raise ValueError(f"'window_seconds' must be >= 0, got {win}")
        else:
            win = None
        if win in (None, 0, 0.0) and probes:
            # Derive window from probe timestamps if not supplied.
            ts = [p.t for p in probes]
            win = max(ts) - min(ts)
        exp_limit_raw = d.get("expected_limit")
        if exp_limit_raw is not None:
            try:
                exp_limit: Optional[int] = int(exp_limit_raw)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"'expected_limit' must be an integer: {exc}") from exc
            if exp_limit < 0:
                raise ValueError(f"'expected_limit' must be >= 0, got {exp_limit}")
        else:
            exp_limit = None
        return Spec(
            target=target,
            method=str(d.get("method", "GET")).upper(),
            window_seconds=float(win or 0.0),
            expected_limit=exp_limit,
            auth_required=bool(d.get("auth_required", False)),
            probes=probes,
        )


@dataclass
class Finding:
    code: str
    severity: str
    title: str
    detail: str
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Report:
    tool: str
    version: str
    target: str
    method: str
    summary: Dict[str, Any]
    findings: List[Finding]

    @property
    def max_severity(self) -> str:
        if not self.findings:
            return "info"
        return max(self.findings, key=lambda f: _SEV_RANK[f.severity]).severity

    @property
    def actionable(self) -> bool:
        """True if any finding is at or above 'low' (worth a non-zero exit)."""
        return any(_SEV_RANK[f.severity] >= _SEV_RANK["low"] for f in self.findings)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": self.tool,
            "version": self.version,
            "target": self.target,
            "method": self.method,
            "max_severity": self.max_severity,
            "actionable": self.actionable,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
        }


def load_spec(path: str) -> Spec:
    """Load and parse a spec file.

    Raises:
        FileNotFoundError: if *path* does not exist.
        ValueError: if the file is not valid JSON or fails spec validation.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as exc:
        raise ValueError(f"spec file is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(
            f"spec must be a JSON object (got {type(data).__name__})"
        )
    return Spec.from_dict(data)


# --------------------------------------------------------------------------- #
# Analysis primitives
# --------------------------------------------------------------------------- #

def _observed_throttle(probes: List[Probe]) -> List[Probe]:
    return [p for p in probes if p.status in _THROTTLE_STATUSES]


def _header_coverage(probes: List[Probe]) -> Tuple[bool, List[str]]:
    """Return (any_present, sorted list of distinct rate-limit headers seen)."""
    seen = set()
    for p in probes:
        for h in p.headers:
            if h in _RATELIMIT_HEADER_HINTS:
                seen.add(h)
    return (len(seen) > 0, sorted(seen))


def _has_retry_after(probes: List[Probe]) -> bool:
    throttled = _observed_throttle(probes)
    return any("retry-after" in p.headers for p in throttled)


def _effective_rate(spec: Spec) -> Optional[float]:
    """Requests-per-second the probe burst sustained, if a window is known."""
    if spec.window_seconds and spec.window_seconds > 0:
        return len(spec.probes) / spec.window_seconds
    return None


# --------------------------------------------------------------------------- #
# Main analysis
# --------------------------------------------------------------------------- #

def analyze_spec(spec: Spec, tool: str = "ratecheck", version: str = "1.0.0") -> Report:
    findings: List[Finding] = []
    probes = spec.probes
    total = len(probes)
    throttled = _observed_throttle(probes)
    accepted = [p for p in probes if 200 <= p.status < 300]
    server_errors = [p for p in probes if 500 <= p.status < 600 and p.status != 503]

    headers_present, header_list = _header_coverage(probes)
    eff_rate = _effective_rate(spec)

    # 1) No throttling observed at all under a burst.
    if total > 0 and not throttled:
        sev = "high" if spec.auth_required else "medium"
        findings.append(
            Finding(
                code="RC001",
                severity=sev,
                title="No rate limiting observed under burst load",
                detail=(
                    f"All {total} probed requests were served without any 429/503 "
                    f"throttle response. The endpoint appears to accept unbounded "
                    f"request bursts"
                    + (" on a sensitive/auth endpoint." if spec.auth_required else ".")
                ),
                evidence={
                    "total_probes": total,
                    "accepted": len(accepted),
                    "throttled": 0,
                    "effective_rps": round(eff_rate, 3) if eff_rate else None,
                },
            )
        )

    # 2) Throttling kicked in but later than the documented limit.
    if spec.expected_limit is not None and total > 0:
        # Index (1-based) of the first throttled response = how many got through.
        first_throttle_idx = None
        for i, p in enumerate(probes, start=1):
            if p.status in _THROTTLE_STATUSES:
                first_throttle_idx = i - 1  # requests accepted before the throttle
                break
        accepted_before = first_throttle_idx if first_throttle_idx is not None else len(accepted)
        if accepted_before > spec.expected_limit:
            findings.append(
                Finding(
                    code="RC002",
                    severity="medium",
                    title="Throttling enforced above the documented limit",
                    detail=(
                        f"{accepted_before} requests were accepted before the first "
                        f"throttle, exceeding the documented per-window limit of "
                        f"{spec.expected_limit}. The limit is not enforced tightly."
                    ),
                    evidence={
                        "accepted_before_throttle": accepted_before,
                        "expected_limit": spec.expected_limit,
                        "overage": accepted_before - spec.expected_limit,
                    },
                )
            )

    # 3) No standard rate-limit headers — clients can't self-pace.
    if total > 0 and not headers_present:
        findings.append(
            Finding(
                code="RC003",
                severity="low",
                title="No standard rate-limit headers exposed",
                detail=(
                    "None of the observed responses carried standard rate-limit "
                    "headers (X-RateLimit-*, RateLimit-*, Retry-After). Well-behaved "
                    "clients cannot discover or respect the limit programmatically."
                ),
                evidence={"recognized_headers": list(_RATELIMIT_HEADER_HINTS)},
            )
        )

    # 4) Throttled without a Retry-After hint.
    if throttled and not _has_retry_after(probes):
        findings.append(
            Finding(
                code="RC004",
                severity="low",
                title="Throttle responses omit Retry-After",
                detail=(
                    f"{len(throttled)} throttle response(s) (429/503) were returned "
                    f"without a Retry-After header, so clients cannot back off "
                    f"cooperatively and may hammer the endpoint."
                ),
                evidence={"throttled_count": len(throttled)},
            )
        )

    # 5) Server errors under load (capacity / robustness problem).
    if server_errors:
        findings.append(
            Finding(
                code="RC005",
                severity="high",
                title="Server errors emitted under burst load",
                detail=(
                    f"{len(server_errors)} response(s) returned 5xx (non-503) status "
                    f"during the burst, indicating the endpoint fails rather than "
                    f"throttles when overloaded."
                ),
                evidence={
                    "error_statuses": sorted({p.status for p in server_errors}),
                    "count": len(server_errors),
                },
            )
        )

    # 6) Healthy posture note (info) when throttling + headers both present.
    if throttled and headers_present and not server_errors:
        findings.append(
            Finding(
                code="RC100",
                severity="info",
                title="Rate limiting appears active",
                detail=(
                    "The endpoint throttled excess requests and exposed rate-limit "
                    "headers. Posture looks healthy for the observed trace."
                ),
                evidence={
                    "throttled_count": len(throttled),
                    "headers_seen": header_list,
                },
            )
        )

    summary = {
        "total_probes": total,
        "accepted_2xx": len(accepted),
        "throttled_429_503": len(throttled),
        "server_errors_5xx": len(server_errors),
        "window_seconds": spec.window_seconds,
        "effective_rps": round(eff_rate, 3) if eff_rate else None,
        "ratelimit_headers_present": headers_present,
        "ratelimit_headers_seen": header_list,
        "findings_count": len(findings),
    }

    return Report(
        tool=tool,
        version=version,
        target=spec.target,
        method=spec.method,
        summary=summary,
        findings=findings,
    )
