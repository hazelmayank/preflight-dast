"""Safety gateway: the ONLY module in ``preflight/`` allowed to perform network I/O.

Every request an agent wants to make goes through ``Gateway.send``. In order, it:

1. checks the kill switch (memory flag + ``out/KILL``);
2. verifies the SHA-256 of the policy files (scope, limits, reserved actions); tampering trips
   the kill switch;
3. checks scope: scheme, host, port and method must be on the allowlist; no URL credentials;
4. holds reserved actions (pay / cancel / refund / role change / supplier callbacks) until a
   human has approved that exact request;
5. rate-limits (token bucket) and honours health backoff (p90 latency / 5xx rate);
6. re-checks the kill switch immediately before sending;
7. sends (no redirects, no proxies, capped body and response size) and writes the request and the
   response to the hash-chained audit log, secrets redacted.

Every refusal is audited too. ``tests/test_egress_guard.py`` fails the build if any other module
under ``preflight/`` imports an HTTP or socket library.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import math
import re
import threading
import time
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import SplitResult, urlsplit

import httpx
import yaml

from .approval import ApprovalQueue, ReservedActions
from .audit import AuditLog, redact_headers, redact_text, redact_url
from .killswitch import KillSwitch, KillSwitchEngaged

SAFETY_DIR = Path(__file__).resolve().parent
USER_AGENT = "Preflight-DAST/0.1 (authorized test of synthetic target)"
_BAD_URL_CHARS = re.compile(r"[\s\x00-\x1f\x7f\\]")
_DEFAULT_PORTS = {"http": 80, "https": 443}


class GatewayError(Exception):
    """Base class for gateway refusals and transport failures."""


class ScopeViolation(GatewayError):
    pass


class RequestRejected(GatewayError):
    pass


class RateLimitExceeded(GatewayError):
    pass


class TransportError(GatewayError):
    pass


class ApprovalRequired(GatewayError):
    def __init__(self, approval_id: str, rule: str):
        super().__init__(f"{rule} needs human approval: {approval_id}")
        self.approval_id, self.rule = approval_id, rule


# -- policy ---------------------------------------------------------------------------------


@dataclass(frozen=True)
class Scope:
    hosts: frozenset[str]
    ports: frozenset[int]
    schemes: frozenset[str]
    methods: frozenset[str]
    llm_hosts: frozenset[str] = frozenset()  # separate, default-empty allowlist for LLM calls
    llm_ports: frozenset[int] = frozenset({443})

    @classmethod
    def from_file(cls, path: Path | str) -> Scope:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        return cls(
            frozenset(str(h).lower() for h in raw.get("allowed_hosts", [])),
            frozenset(int(p) for p in raw.get("allowed_ports", [])),
            frozenset(str(s).lower() for s in raw.get("allowed_schemes", ["http"])),
            frozenset(str(m).upper() for m in raw.get("allowed_methods", ["GET"])),
            frozenset(str(h).lower() for h in raw.get("llm_hosts", [])),
            frozenset(int(p) for p in raw.get("llm_ports", [443])),
        )

    def check_llm(self, method: str, url: str) -> SplitResult:
        """LLM channel: https POST to an explicitly allowlisted host only."""
        if _BAD_URL_CHARS.search(url):
            raise ScopeViolation("illegal characters in URL")
        try:
            parts = urlsplit(url)
            port = parts.port
        except ValueError:
            raise ScopeViolation("malformed URL") from None
        host = (parts.hostname or "").rstrip(".").lower()
        if parts.scheme.lower() != "https" or parts.username is not None:
            raise ScopeViolation("LLM channel is https only, no URL credentials")
        if host not in self.llm_hosts:
            raise ScopeViolation(f"LLM host {host!r} is not allowlisted (llm_hosts is empty by default)")
        if (port or 443) not in self.llm_ports or method != "POST":
            raise ScopeViolation("LLM channel allows POST on allowlisted ports only")
        return parts

    def check(self, method: str, url: str) -> SplitResult:
        """Return the parsed URL or raise ScopeViolation. Never resolves or connects."""
        if _BAD_URL_CHARS.search(url):
            raise ScopeViolation("illegal characters in URL")
        try:
            parts = urlsplit(url)
            port = parts.port
        except ValueError:
            raise ScopeViolation("malformed URL") from None
        scheme = parts.scheme.lower()
        if scheme not in self.schemes:
            raise ScopeViolation(f"scheme {scheme!r} not allowed")
        if parts.username is not None or parts.password is not None:
            raise ScopeViolation("credentials in URL not allowed")
        host = (parts.hostname or "").rstrip(".").lower()
        if host not in self.hosts:
            raise ScopeViolation(f"host {host!r} is outside the approved scope")
        if (port or _DEFAULT_PORTS.get(scheme, 0)) not in self.ports:
            raise ScopeViolation(f"port {port or _DEFAULT_PORTS.get(scheme)} is not allowed")
        if method not in self.methods:
            raise ScopeViolation(f"method {method} not allowed")
        return parts


@dataclass(frozen=True)
class Limits:
    rps: float
    burst: int
    max_wait_s: float
    window: int
    min_samples: int
    p90_ms: float
    error_rate: float
    backoff_initial_s: float
    backoff_max_s: float
    backoff_mult: float
    recover_after: int
    timeout_s: float
    max_body: int
    max_response: int
    max_concurrency: int

    @classmethod
    def from_file(cls, path: Path | str) -> Limits:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        rl, h, rq = raw.get("rate_limit", {}), raw.get("health", {}), raw.get("request", {})
        return cls(
            float(rl.get("requests_per_second", 5)), int(rl.get("burst", 10)),
            float(rl.get("max_wait_seconds", 30)),
            int(h.get("window", 20)), int(h.get("min_samples", 8)),
            float(h.get("p90_latency_ms", 1500)), float(h.get("error_rate", 0.5)),
            float(h.get("backoff_initial_seconds", 1)), float(h.get("backoff_max_seconds", 30)),
            float(h.get("backoff_multiplier", 2)), int(h.get("recover_after_healthy", 5)),
            float(rq.get("timeout_seconds", 10)), int(rq.get("max_body_bytes", 65536)),
            int(rq.get("max_response_bytes", 1048576)), int(rq.get("max_concurrency", 2)),
        )


class PolicyIntegrity:
    """SHA-256 of each policy file at start-up; ``changed`` names any that differ later."""

    def __init__(self, paths: Mapping[str, Path]):
        self._paths = dict(paths)
        self.hashes = {n: self._hash(p) for n, p in self._paths.items()}

    @staticmethod
    def _hash(path: Path) -> str:
        try:
            return hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            return "missing"

    def changed(self) -> str | None:
        for name, path in self._paths.items():
            if self._hash(path) != self.hashes[name]:
                return name
        return None


# -- rate limiting and health ---------------------------------------------------------------


class TokenBucket:
    def __init__(self, rate: float, burst: int, clock: Callable[[], float]):
        self.rate, self.burst, self._clock = rate, float(burst), clock
        self._tokens, self._last = float(burst), clock()
        self._lock = threading.Lock()

    def reserve(self, max_wait: float) -> float:
        """Take a token; return seconds to wait first. Raise if that exceeds ``max_wait``."""
        with self._lock:
            now = self._clock()
            self._tokens = min(self.burst, self._tokens + (now - self._last) * self.rate)
            self._last = now
            wait = 0.0 if self._tokens >= 1 else (1 - self._tokens) / self.rate
            if wait > max_wait:
                raise RateLimitExceeded(f"would need to wait {wait:.1f}s (max {max_wait:.0f}s)")
            self._tokens -= 1
            return wait


class HealthMonitor:
    """Backs off, exponentially, when the target looks strained (p90 latency or 5xx rate)."""

    def __init__(self, cfg: Limits, clock: Callable[[], float]):
        self.cfg, self._clock = cfg, clock
        self._samples: deque[tuple[float, bool]] = deque(maxlen=cfg.window)
        self._delay, self._until, self._streak = cfg.backoff_initial_s, 0.0, 0

    def record(self, latency_ms: float, error: bool) -> dict[str, float] | None:
        self._samples.append((latency_ms, error))
        if len(self._samples) < self.cfg.min_samples:
            return None
        lat = sorted(s[0] for s in self._samples)
        p90 = lat[max(0, math.ceil(0.9 * len(lat)) - 1)]
        err = sum(1 for s in self._samples if s[1]) / len(self._samples)
        if p90 > self.cfg.p90_ms or err > self.cfg.error_rate:
            wait = self._delay
            self._until = self._clock() + wait
            self._delay = min(self._delay * self.cfg.backoff_mult, self.cfg.backoff_max_s)
            self._streak = 0
            self._samples.clear()  # judge recovery on fresh samples, not the ones that tripped it
            return {"p90_ms": p90, "error_rate": err, "wait_s": wait}
        self._streak += 1
        if self._streak >= self.cfg.recover_after:
            self._delay = self.cfg.backoff_initial_s
        return None

    def remaining(self) -> float:
        return max(0.0, self._until - self._clock())


# -- the gateway ----------------------------------------------------------------------------


@dataclass(frozen=True)
class GatewayResponse:
    status: int
    headers: dict[str, str]
    body: bytes
    elapsed_ms: float
    request_id: str
    url: str

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def json(self) -> Any:
        return json.loads(self.body)


class Gateway:
    def __init__(
        self,
        *,
        out_dir: Path | str = "out",
        scope_path: Path | str = SAFETY_DIR / "scope.yaml",
        limits_path: Path | str = SAFETY_DIR / "limits.yaml",
        reserved_path: Path | str = SAFETY_DIR / "reserved_actions.yaml",
        transport: httpx.BaseTransport | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        wall_clock: Callable[[], float] = time.time,
    ):
        out = Path(out_dir)
        self._clock, self._sleep = clock, sleep
        self.scope = Scope.from_file(scope_path)
        self.limits = Limits.from_file(limits_path)
        self.reserved = ReservedActions.from_file(reserved_path)
        self._integrity = PolicyIntegrity(
            {"scope": Path(scope_path), "limits": Path(limits_path),
             "reserved_actions": Path(reserved_path)}
        )
        self.killswitch = KillSwitch(out / "KILL")
        self.audit = AuditLog(out / "audit.jsonl", wall_clock)
        self.approvals = ApprovalQueue(out / "approvals.json", self.reserved.ttl_s, wall_clock)
        self._bucket = TokenBucket(self.limits.rps, self.limits.burst, clock)
        self._health = HealthMonitor(self.limits, clock)
        self._slots = threading.BoundedSemaphore(self.limits.max_concurrency)
        self._ids = itertools.count(1)
        self.stats = {"sent": 0, "refused": 0, "held": 0}
        self._client = httpx.Client(
            transport=transport, timeout=self.limits.timeout_s, follow_redirects=False,
            trust_env=False, headers={"User-Agent": USER_AGENT},
        )
        self.audit.append("gateway_start", policy_sha256=self._integrity.hashes,
                          scope={"hosts": sorted(self.scope.hosts),
                                 "ports": sorted(self.scope.ports)})

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> Gateway:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- public API -----------------------------------------------------------------------
    def send(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        json_body: Any = None,
        content: bytes | None = None,
        params: Mapping[str, Any] | None = None,
        actor: str = "agent",
        purpose: str = "",
        approval_id: str | None = None,
        channel: str = "target",
    ) -> GatewayResponse:
        method = method.upper()
        rid = f"req-{next(self._ids):06d}"
        ctx = {"id": rid, "actor": actor, "purpose": purpose, "method": method,
               "url": redact_url(url), "channel": channel}

        self._guard_kill(ctx)
        self._guard_integrity(ctx)
        try:
            if channel == "llm":
                parts = self.scope.check_llm(method, url)
            elif channel == "target":
                parts = self.scope.check(method, url)
            else:
                raise ScopeViolation(f"unknown channel {channel!r}")
            body, hdrs = self._prepare(json_body, content, headers)
        except GatewayError as exc:
            self._refuse(ctx, exc)
            raise
        if channel == "target":
            self._guard_approval(method, parts, url, params, body, approval_id, ctx)

        with self._slots:
            self._pace(ctx)
            self._guard_kill(ctx)  # last check, immediately before the bytes leave
            return self._transmit(rid, ctx, method, url, hdrs, params, body)

    # -- guards ---------------------------------------------------------------------------
    def _refuse(self, ctx: dict, exc: Exception) -> None:
        self.stats["refused"] += 1
        self.audit.append("refused", reason=type(exc).__name__, detail=str(exc), **ctx)

    def _guard_kill(self, ctx: dict) -> None:
        if self.killswitch.is_engaged():
            exc = KillSwitchEngaged(self.killswitch.reason())
            self._refuse(ctx, exc)
            raise exc

    def _guard_integrity(self, ctx: dict) -> None:
        changed = self._integrity.changed()
        if changed:
            self.killswitch.engage(f"policy file tampered: {changed}", by="gateway")
            self.audit.append("killswitch", reason=f"policy file tampered: {changed}")
            self._guard_kill(ctx)

    def _prepare(self, json_body: Any, content: bytes | None, headers: Mapping[str, str] | None):
        hdrs = dict(headers or {})
        if any(k.lower() == "host" for k in hdrs):
            raise RequestRejected("overriding the Host header is not allowed")
        body = content if content is not None else b""
        if json_body is not None:
            body = json.dumps(json_body, separators=(",", ":")).encode()
            hdrs.setdefault("Content-Type", "application/json")
        if len(body) > self.limits.max_body:
            raise RequestRejected(f"body of {len(body)} bytes exceeds {self.limits.max_body}")
        return body, hdrs

    def _guard_approval(self, method, parts, url, params, body, approval_id, ctx) -> None:
        rule = self.reserved.match(method, parts.path)
        if rule is None:
            return
        fp = ApprovalQueue.fingerprint(method, url, params, body)
        if approval_id and self.approvals.is_approved(approval_id, fp):
            self.approvals.consume(approval_id)
            self.audit.append("approval_used", approval_id=approval_id, rule=rule, **ctx)
            return
        rec = self.approvals.request(rule, method, redact_url(url), fp, ctx["actor"], ctx["purpose"])
        self.stats["held"] += 1
        self.audit.append("held", approval_id=rec["id"], rule=rule, status=rec["status"], **ctx)
        raise ApprovalRequired(rec["id"], rule)

    def _pace(self, ctx: dict) -> None:
        """Wait for a rate-limit token and for any health backoff, staying kill-switch aware."""
        try:
            wait = self._bucket.reserve(self.limits.max_wait_s)
        except RateLimitExceeded as exc:
            self._refuse(ctx, exc)
            raise
        if wait:
            self._interruptible_sleep(wait, ctx)
        backoff = self._health.remaining()
        if backoff:
            self.audit.append("backoff_wait", wait_s=round(backoff, 3), **ctx)
            self._interruptible_sleep(backoff, ctx)

    def _interruptible_sleep(self, seconds: float, ctx: dict) -> None:
        end = self._clock() + seconds
        while (left := end - self._clock()) > 0:
            self._guard_kill(ctx)
            self._sleep(min(0.25, left))

    # -- the one place bytes leave --------------------------------------------------------
    def _transmit(self, rid, ctx, method, url, hdrs, params, body) -> GatewayResponse:
        self.audit.append(
            "request", headers=redact_headers(hdrs),
            params=json.loads(redact_text(json.dumps(dict(params or {})))),
            body=redact_text(body.decode("utf-8", errors="replace"),
                             300 if ctx["channel"] == "llm" else 1000) if body else "", **ctx,
        )
        self.stats["sent"] += 1
        start = self._clock()
        try:
            with self._client.stream(method, url, headers=hdrs, params=params,
                                     content=body or None) as resp:
                chunks, size = [], 0
                for chunk in resp.iter_bytes():
                    chunks.append(chunk)
                    size += len(chunk)
                    if size > self.limits.max_response:
                        break
                status, rheaders = resp.status_code, dict(resp.headers)
        except httpx.HTTPError as exc:
            elapsed = (self._clock() - start) * 1000
            self._note_health(elapsed, True, ctx)
            self.audit.append("response", id=rid, error=type(exc).__name__, detail=str(exc),
                              elapsed_ms=round(elapsed, 1))
            raise TransportError(f"{type(exc).__name__}: {exc}") from exc

        elapsed = (self._clock() - start) * 1000
        data = b"".join(chunks)[: self.limits.max_response]
        self._note_health(elapsed, status >= 500, ctx)
        self.audit.append(
            "response", id=rid, status=status, elapsed_ms=round(elapsed, 1), bytes=len(data),
            headers=redact_headers({k: v for k, v in rheaders.items()
                                    if k.lower() in ("content-type", "location", "set-cookie")}),
            body=redact_text(data.decode("utf-8", errors="replace")),
        )
        return GatewayResponse(status, rheaders, data, elapsed, rid, url)

    def _note_health(self, elapsed_ms: float, error: bool, ctx: dict) -> None:
        tripped = self._health.record(elapsed_ms, error)
        if tripped:
            self.audit.append("backoff", **tripped, id=ctx["id"])
