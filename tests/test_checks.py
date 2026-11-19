"""The 8 property checks against the live target: unsafe in the vulnerable build, clean when fixed."""

import json
import re
import socket
import threading
import time
from pathlib import Path

import httpx
import pytest
import uvicorn

from preflight.discovery.invariants import propose_invariants
from preflight.discovery.rulebook import Rulebook
from preflight.execution import verifier
from preflight.execution.client import ApiClient, Inconclusive
from preflight.execution.flow import Flow
from preflight.execution.oracle import Account, CheckContext, CheckResult
from preflight.execution.verifier import verify
from preflight.llm import RecordedLLM
from preflight.planning.planner import plan_checks
from preflight.recon.har_parser import load_steps
from preflight.safety.audit import AuditLog
from preflight.safety.gateway import Gateway
from target import gen_data
from target.app import app
from target.store import DEPLOY_TOKEN, PASSWORD

REC = Path(__file__).resolve().parent.parent / "demo" / "recordings"

# what each check must conclude on the vulnerable build (spec variations, unmodified)
VULNERABLE = {"INV-01": "finding", "INV-02": "finding", "INV-03": "finding", "INV-04": "clean",
              "INV-05": "finding", "INV-06": "clean", "INV-07": "clean", "INV-08": "finding"}


@pytest.fixture(scope="module")
def live(tmp_path_factory):
    d = tmp_path_factory.mktemp("live")
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    from tests.conftest import SAFETY

    for name in ("scope.yaml", "limits.yaml", "reserved_actions.yaml"):
        text = (SAFETY / name).read_text()
        text = re.sub(r"- 8000", f"- {port}", text).replace("requests_per_second: 5",
                                                            "requests_per_second: 500")
        text = text.replace("burst: 10", "burst: 500")
        (d / name).write_text(text)
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    while not server.started:
        time.sleep(0.05)
    (d / "j.har").write_text(json.dumps(gen_data.journeys()))
    yield d, f"http://127.0.0.1:{port}"
    server.should_exit = True
    t.join(timeout=5)


def deploy(base, mode):
    r = httpx.post(base + "/_deploy", headers={"x-deploy-token": DEPLOY_TOKEN},
                   json={"version": "t", "mode": mode, "reset": True})
    assert r.status_code == 200


@pytest.fixture
def harness(live, api_map_dict, tmp_path):
    d, base = live
    gw = Gateway(out_dir=tmp_path / "out", scope_path=d / "scope.yaml", limits_path=d / "limits.yaml",
                 reserved_path=d / "reserved_actions.yaml")
    stop = threading.Event()

    def operator():  # stands in for the human who approves reserved actions
        while not stop.is_set():
            for rec in gw.approvals.pending():
                gw.approvals.approve(rec["id"], "test-operator")
            time.sleep(0.02)

    threading.Thread(target=operator, daemon=True).start()
    client = ApiClient(gw, base, approval_wait_s=20)
    accounts = [Account(f"{t}_{r}", t, r, f"{e}@{t}.test", PASSWORD)
                for t in ("acme", "beta") for r, e in
                (("admin", "admin"), ("agent", "agent"), ("sub_agent", "sub"))]
    ctx = CheckContext(client, Flow(client, load_steps(d / "j.har")), accounts, api_map_dict)
    book = Rulebook(tmp_path / "rb.json")
    llm = RecordedLLM(REC)
    book.propose(propose_invariants(llm, api_map_dict))
    book.confirm_invariants("alice")
    book.confirm_low_confidence("INV-08", "alice")
    plans = {p.invariant_id: p for p in plan_checks(llm, book.confirmed()).plans}
    yield base, ctx, plans, gw
    stop.set()
    gw.close()


@pytest.mark.parametrize("inv", sorted(VULNERABLE))
def test_vulnerable_build(harness, inv):
    base, ctx, plans, gw = harness
    deploy(base, "vulnerable")
    v = verify(ctx, plans[inv])
    assert v.status == VULNERABLE[inv], (inv, v.status, v.reason)
    if v.status == "finding":
        f = v.finding
        assert f.reproduced == 2 and f.control and f.proof and f.curl.startswith("curl ")
        assert "Bearer eyJ" not in json.dumps(f.to_dict())  # no secrets in evidence


@pytest.mark.parametrize("inv", sorted(VULNERABLE))
def test_fixed_build_is_clean(harness, inv):
    base, ctx, plans, gw = harness
    deploy(base, "fixed")
    v = verify(ctx, plans[inv])
    assert v.status == "clean", (inv, v.status, v.reason)


def test_everything_went_through_the_gateway_and_was_audited(harness):
    base, ctx, plans, gw = harness
    deploy(base, "vulnerable")
    verify(ctx, plans["INV-01"])
    assert AuditLog.verify(gw.audit.path).ok
    assert gw.stats["sent"] > 5 and gw.stats["held"] >= 1  # refunds/pay/cancel were held for approval
    events = [json.loads(line) for line in gw.audit.path.read_text().splitlines()]
    assert any(e["event"] == "approval_used" for e in events)


def test_kill_switch_stops_a_check_midway(harness):
    from preflight.safety.killswitch import KillSwitchEngaged

    base, ctx, plans, gw = harness
    deploy(base, "vulnerable")
    gw.killswitch.engage("test")
    with pytest.raises(KillSwitchEngaged):
        verify(ctx, plans["INV-02"])


# -- verifier logic ---------------------------------------------------------------------------
def _fake(results):
    seq = iter(results)

    def check(ctx, plan, with_control):
        r = next(seq)
        if isinstance(r, Exception):
            raise r
        return r

    return check


def _plan():
    from preflight.discovery.invariant_schema import CheckPlan

    return CheckPlan(invariant_id="INV-01", check="refund_bound", method="POST",
                     endpoint="/api/v1/bookings/{booking_id}/refunds")


def _ex(label="v"):
    from preflight.execution.client import Exchange

    return Exchange(label, "a", "POST", "/x", "http://127.0.0.1:8000/x", 200, {"a": 1}, raw="{}")


@pytest.mark.parametrize(
    "results,status",
    [
        ([CheckResult("INV-01", True, False, [_ex()])], "inconclusive"),  # control failed
        ([CheckResult("INV-01", False, True, [_ex()])], "clean"),
        ([CheckResult("INV-01", True, True, [_ex()]), CheckResult("INV-01", False, None, [_ex()])],
         "inconclusive"),  # did not reproduce
        ([Inconclusive("setup failed")], "inconclusive"),
        ([CheckResult("INV-01", True, True, [_ex()], control=[_ex("c")]),
          CheckResult("INV-01", True, None, [_ex()])], "finding"),
    ],
)
def test_verifier_needs_two_violations_and_a_passing_control(monkeypatch, results, status):
    monkeypatch.setitem(verifier.REGISTRY, "refund_bound", _fake(results))
    assert verify(None, _plan()).status == status
