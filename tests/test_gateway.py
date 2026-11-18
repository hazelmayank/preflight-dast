import json

import httpx
import pytest

from preflight.safety.audit import AuditLog
from preflight.safety.gateway import (
    ApprovalRequired,
    Gateway,
    RateLimitExceeded,
    RequestRejected,
    ScopeViolation,
    TransportError,
)
from preflight.safety.killswitch import KillSwitchEngaged

BASE = "http://127.0.0.1:8000"


class Clock:
    """Fake monotonic clock: sleeping advances time instantly."""

    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.t += s


def make(policy, tmp_path, handler=None, clock=None):
    seen = []

    def default(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"ok": True})

    def wrapped(request):
        if handler is None:
            return default(request)
        seen.append(request)
        return handler(request)

    clock = clock or Clock()
    gw = Gateway(
        out_dir=tmp_path / "out",
        scope_path=policy / "scope.yaml",
        limits_path=policy / "limits.yaml",
        reserved_path=policy / "reserved_actions.yaml",
        transport=httpx.MockTransport(wrapped),
        clock=clock,
        sleep=clock.sleep,
    )
    return gw, seen, clock


def events(gw):
    return [json.loads(line) for line in gw.audit.path.read_text().splitlines()]


# -- scope ----------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "url",
    [
        "http://evil.example/",
        "http://127.0.0.1:9999/",  # wrong port
        "https://127.0.0.1:8000/",  # wrong scheme
        "http://127.0.0.1@evil.example/",  # userinfo trick
        "http://evil.example#@127.0.0.1:8000/",
        "http://127.0.0.1:8000\\@evil.example/",
        "http://2130706433:8000/",  # decimal IP form of 127.0.0.1
        "http://[::1]:8000/",  # not in the allowlist
        "http://localhost.evil.example:8000/",
        "ftp://127.0.0.1:8000/",
        "http://127.0.0.1:8000/a b",
        "file:///etc/passwd",
    ],
)
def test_out_of_scope_refused_and_never_sent(policy, tmp_path, url):
    gw, seen, _ = make(policy, tmp_path)
    with pytest.raises(ScopeViolation):
        gw.send("GET", url)
    assert seen == [] and gw.stats["sent"] == 0 and gw.stats["refused"] == 1
    assert events(gw)[-1]["event"] == "refused"


def test_in_scope_request_is_sent_and_audited(policy, tmp_path):
    gw, seen, _ = make(policy, tmp_path)
    r = gw.send("GET", f"{BASE}/api/v1/search", params={"city": "Goa"}, purpose="t")
    assert r.status == 200 and r.json() == {"ok": True} and len(seen) == 1
    assert [e["event"] for e in events(gw)] == ["gateway_start", "request", "response"]
    assert AuditLog.verify(gw.audit.path).ok
    assert seen[0].headers["user-agent"].startswith("Preflight-DAST")


def test_redirects_are_not_followed(policy, tmp_path):
    gw, seen, _ = make(
        policy, tmp_path, lambda r: httpx.Response(302, headers={"location": "http://evil.example/"})
    )
    assert gw.send("GET", f"{BASE}/x").status == 302
    assert len(seen) == 1


def test_secrets_redacted_in_audit(policy, tmp_path):
    gw, _, _ = make(policy, tmp_path)
    gw.send(
        "POST", f"{BASE}/api/v1/auth/login",
        headers={"Authorization": "Bearer supersecrettoken"},
        json_body={"email": "a@b.test", "password": "hunter2"},
    )
    raw = gw.audit.path.read_text()
    assert "hunter2" not in raw and "supersecrettoken" not in raw


def test_host_header_override_and_oversize_refused(policy, tmp_path):
    gw, seen, _ = make(policy, tmp_path)
    with pytest.raises(RequestRejected):
        gw.send("GET", f"{BASE}/x", headers={"Host": "evil.example"})
    with pytest.raises(RequestRejected):
        gw.send("POST", f"{BASE}/x", content=b"x" * 70000)
    assert seen == []


def test_transport_error_is_audited_and_counts_against_health(policy, tmp_path):
    def boom(request):
        raise httpx.ConnectError("down")

    gw, _, _ = make(policy, tmp_path, boom)
    with pytest.raises(TransportError):
        gw.send("GET", f"{BASE}/x")
    assert events(gw)[-1]["data"]["error"] == "ConnectError"


# -- kill switch ----------------------------------------------------------------------------
def test_kill_flag_halts_run(policy, tmp_path):
    gw, seen, _ = make(policy, tmp_path)
    gw.send("GET", f"{BASE}/a")
    gw.killswitch.engage("test")
    with pytest.raises(KillSwitchEngaged):
        gw.send("GET", f"{BASE}/b")
    assert len(seen) == 1


def test_kill_file_from_outside_halts_run(policy, tmp_path):
    gw, seen, _ = make(policy, tmp_path)
    gw.send("GET", f"{BASE}/a")
    (tmp_path / "out" / "KILL").write_text("operator")
    with pytest.raises(KillSwitchEngaged):
        gw.send("GET", f"{BASE}/b")
    assert len(seen) == 1


def test_kill_during_rate_limit_wait_stops_the_send(policy, tmp_path):
    gw, seen, clock = make(policy, tmp_path)
    for _ in range(10):  # drain the burst
        gw.send("GET", f"{BASE}/a")
    orig = clock.sleep
    clock.sleep = lambda s: (gw.killswitch.engage("mid-wait"), orig(s))[1]
    gw._sleep = clock.sleep
    with pytest.raises(KillSwitchEngaged):
        gw.send("GET", f"{BASE}/a")
    assert len(seen) == 10


def test_scope_tamper_trips_kill_switch(policy, tmp_path):
    gw, seen, _ = make(policy, tmp_path)
    gw.send("GET", f"{BASE}/a")
    (policy / "scope.yaml").write_text(
        (policy / "scope.yaml").read_text() + "\n# widened\n"
    )
    with pytest.raises(KillSwitchEngaged):
        gw.send("GET", f"{BASE}/b")
    assert gw.killswitch.is_engaged() and "tampered" in gw.killswitch.reason()
    assert len(seen) == 1
    assert any(e["event"] == "killswitch" for e in events(gw))
    # stays dead even though the file is restored
    with pytest.raises(KillSwitchEngaged):
        gw.send("GET", f"{BASE}/c")


# -- approvals ------------------------------------------------------------------------------
def test_reserved_action_held_until_human_approves(policy, tmp_path):
    gw, seen, _ = make(policy, tmp_path)
    url = f"{BASE}/api/v1/bookings/BK-1/refunds"
    with pytest.raises(ApprovalRequired) as held:
        gw.send("POST", url, json_body={"amount": 5})
    aid = held.value.approval_id
    assert seen == []
    with pytest.raises(ApprovalRequired):  # pending is not approved
        gw.send("POST", url, json_body={"amount": 5}, approval_id=aid)
    gw.approvals.approve(aid, "alice")
    with pytest.raises(ApprovalRequired):  # approval does not cover a different body
        gw.send("POST", url, json_body={"amount": 5000}, approval_id=aid)
    assert gw.send("POST", url, json_body={"amount": 5}, approval_id=aid).status == 200
    assert len(seen) == 1
    with pytest.raises(ApprovalRequired):  # single use
        gw.send("POST", url, json_body={"amount": 5}, approval_id=aid)
    assert len(seen) == 1


def test_non_reserved_state_change_is_not_held(policy, tmp_path):
    gw, seen, _ = make(policy, tmp_path)
    gw.send("POST", f"{BASE}/api/v1/holds", json_body={"offer_id": 1})
    assert len(seen) == 1


# -- rate limit and health ------------------------------------------------------------------
def test_token_bucket_paces_requests(policy, tmp_path):
    gw, _, clock = make(policy, tmp_path)
    for _ in range(10):
        gw.send("GET", f"{BASE}/a")
    assert clock.t == 0  # burst of 10 is free
    for _ in range(5):
        gw.send("GET", f"{BASE}/a")
    assert clock.t == pytest.approx(1.0, abs=0.05)  # 5 more at 5 rps


def test_rate_limit_wait_cap_refuses(policy, tmp_path):
    (policy / "limits.yaml").write_text(
        (policy / "limits.yaml").read_text().replace("max_wait_seconds: 30", "max_wait_seconds: 0.1")
    )
    gw, _, _ = make(policy, tmp_path)
    for _ in range(10):
        gw.send("GET", f"{BASE}/a")
    with pytest.raises(RateLimitExceeded):
        gw.send("GET", f"{BASE}/a")


def test_health_backoff_on_server_errors(policy, tmp_path):
    gw, seen, clock = make(policy, tmp_path, lambda r: httpx.Response(503))
    for _ in range(8):
        gw.send("GET", f"{BASE}/a")
    assert any(e["event"] == "backoff" for e in events(gw))
    before = clock.t
    gw.send("GET", f"{BASE}/a")
    assert clock.t - before >= 1.0  # waited out the backoff
    assert any(e["event"] == "backoff_wait" for e in events(gw))


def test_4xx_does_not_trigger_backoff(policy, tmp_path):
    gw, _, _ = make(policy, tmp_path, lambda r: httpx.Response(403))
    for _ in range(12):
        gw.send("GET", f"{BASE}/a")
    assert not any(e["event"] == "backoff" for e in events(gw))


def test_slow_target_triggers_backoff(policy, tmp_path):
    clock = Clock()

    def slow(request):
        clock.t += 2.0  # 2000 ms > 1500 ms p90 threshold
        return httpx.Response(200)

    gw, _, _ = make(policy, tmp_path, slow, clock)
    for _ in range(8):
        gw.send("GET", f"{BASE}/a")
    assert any(e["event"] == "backoff" for e in events(gw))
