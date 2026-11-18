"""End-to-end: gateway -> real HTTP -> running synthetic target, with the safety rules biting."""

import re
import socket
import threading
import time

import pytest
import uvicorn

from preflight.safety.audit import AuditLog
from preflight.safety.gateway import ApprovalRequired, Gateway, ScopeViolation
from preflight.safety.killswitch import KillSwitchEngaged
from target.app import app
from target.store import PASSWORD


@pytest.fixture
def live(policy, tmp_path):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    scope = policy / "scope.yaml"
    scope.write_text(re.sub(r"- 8000", f"- {port}", scope.read_text()))
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    gw = Gateway(
        out_dir=tmp_path / "out",
        scope_path=scope,
        limits_path=policy / "limits.yaml",
        reserved_path=policy / "reserved_actions.yaml",
    )
    yield gw, f"http://127.0.0.1:{port}"
    gw.close()
    server.should_exit = True
    thread.join(timeout=5)


def test_safety_rules_hold_against_a_live_target(live, tmp_path):
    gw, base = live
    r = gw.send("POST", f"{base}/api/v1/auth/login",
                json_body={"email": "admin@acme.test", "password": PASSWORD})
    assert r.status == 200
    auth = {"Authorization": "Bearer " + r.json()["token"]}
    assert gw.send("GET", f"{base}/api/v1/bookings/BK-1001", headers=auth).status == 200

    with pytest.raises(ScopeViolation):  # a different host is refused, nothing is sent
        gw.send("GET", "http://example.com/")
    with pytest.raises(ApprovalRequired):  # a refund is held for a human
        gw.send("POST", f"{base}/api/v1/bookings/BK-1002/refunds", headers=auth,
                json_body={"amount": 1})
    assert gw.stats == {"sent": 2, "refused": 1, "held": 1}

    (tmp_path / "out" / "KILL").write_text("operator")  # the kill file halts the run
    with pytest.raises(KillSwitchEngaged):
        gw.send("GET", f"{base}/api/v1/me", headers=auth)
    assert gw.stats["sent"] == 2

    raw = gw.audit.path.read_text()
    assert PASSWORD not in raw and auth["Authorization"].split()[1] not in raw
    assert AuditLog.verify(gw.audit.path).ok
