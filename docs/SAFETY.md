# Safety

Everything the agent sends passes `Gateway.send` in `preflight/safety/gateway.py`.

## Order of checks (per request)

1. Kill switch (memory flag or `out/KILL`).
2. Policy-file SHA-256 (`scope.yaml`, `limits.yaml`, `reserved_actions.yaml`) against the hash taken
   at start-up. A mismatch engages the kill switch; it stays engaged even if the file is restored.
3. Scope: scheme, host, port, method must be allowlisted. URL credentials, control characters,
   backslashes, and `Host` header overrides are refused. Hosts are matched as written, never
   resolved, so `2130706433` or `localhost.evil.example` do not pass.
4. Body size cap.
5. Reserved actions (payment, cancellation, refund, role change, supplier callback): held until a
   human approves that exact request (method, URL, params, body hash). Single use, 15 min expiry.
6. Token bucket (default 5 rps, burst 10); waits above `max_wait_seconds` are refused.
7. Health backoff: exponential when p90 latency or 5xx rate crosses a threshold. 4xx never counts,
   because security tests expect them.
8. Kill switch again, immediately before the bytes leave. Waits are sliced so a kill during a wait
   stops the send.
9. Send: no redirects, no proxies (`trust_env=False`), response size capped.
10. Audit the request and response; refusals are audited too.

## Guards that fail the build

| Test | Fails when |
|---|---|
| `test_egress_guard.py` | any file in `preflight/` except `gateway.py` imports `requests`, `httpx`, `urllib`, `urllib3`, `aiohttp`, `socket`, `http.client`, `subprocess`, etc., calls `os.system`, or uses a dynamic import |
| `test_seed_isolation.py` | `preflight/` imports `seeds`, `target` or `bench`, or names a `seeds/` path |
| `test_no_auto_approve.py` | agent code calls `approve` or `human_release` (only `approval.py`, `killswitch.py`, and `ui/` may) |

Consequence of the strict egress rule: URL parsing helpers (`urllib.parse`) are also gateway-only.
Other modules that need URL parts should get them from the gateway or use plain string handling.

## Human operations

```
python -m preflight.safety.approval list
python -m preflight.safety.approval approve apr-xxxx --by <your name>
python -m preflight.safety.killswitch engage | release | status
```

Approver names that look like agents (`agent*`, `bot*`, `auto*`, `preflight*`, ...) are rejected.

## Known limits

- The approval file is plain JSON on disk. The no-auto-approve guarantee is the static test plus
  process separation, not cryptography.
- The scope check trusts the hostname string; a DNS-rebinding `localhost` is out of scope for a
  localhost-only target.
