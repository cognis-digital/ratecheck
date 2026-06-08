# Demo 01 — Basic: unthrottled login endpoint

## Context

An authorized tester captured a controlled burst of 12 requests against a
login endpoint over a ~0.55s window. The endpoint is documented to allow
**5 requests per second** and is auth-sensitive (`auth_required: true`).

The probe trace (`login_burst.json`) records each observed response. RATECHECK
**does not send traffic** — it triages the evidence you supply.

## What the trace shows

Every one of the 12 requests returned `401 Unauthorized` (bad credentials),
and **none** were throttled (no `429`/`503`). The server happily accepted an
unbounded burst of failed login attempts with no rate-limit headers — a classic
credential-stuffing / brute-force exposure.

## Run it

```
python -m ratecheck check demos/01-basic/login_burst.json
python -m ratecheck check demos/01-basic/login_burst.json --format json
```

## Expected findings

- **RC001 (HIGH)** — No rate limiting observed under burst load (auth endpoint).
- **RC003 (LOW)** — No standard rate-limit headers exposed.

Exit code is `1` because actionable findings (severity >= low) were detected.

## Exit codes

- `0` — no actionable findings (clean / info only)
- `1` — one or more actionable findings (severity >= low)
- `2` — usage / input error

## Fix guidance

Add per-IP / per-account rate limiting on the login route, return `429` with a
`Retry-After` header once the limit is hit, and emit `RateLimit-*` headers so
well-behaved clients can self-pace.

## Scope

This is analysis/triage of a **static, already-captured** probe trace. The tool
makes no network connections and generates no attack traffic — appropriate for
authorized testing and defensive review only.
