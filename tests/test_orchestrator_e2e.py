"""The full loop in-process: detect -> map -> propose -> confirm -> check -> ticket -> fix -> auto-close."""

import json
import re
import socket
import threading
import time
from pathlib import Path

import httpx
import pytest
import uvicorn

from preflight.discovery.rulebook import Rulebook
from preflight.execution.oracle import Account
from preflight.llm import RecordedLLM
from preflight.orchestrator.config import Config
from preflight.orchestrator.machine import Orchestrator
from preflight.safety.approval import ApprovalQueue
from preflight.safety.gateway import Gateway
from target import gen_data
from target.app import app
from target.store import DEPLOY_TOKEN, PASSWORD
from tests.conftest import SAFETY

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def rig(tmp_path):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    pol = tmp_path / "policy"
    pol.mkdir()
    for name in ("scope.yaml", "limits.yaml", "reserved_actions.yaml"):
        t = (SAFETY / name).read_text()
        t = re.sub(r"- 8000", f"- {port}", t).replace("requests_per_second: 5", "requests_per_second: 500")
        (pol / name).write_text(t.replace("burst: 10", "burst: 500"))
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    th = threading.Thread(target=server.run, daemon=True)
    th.start()
    while not server.started:
        time.sleep(0.05)
    base = f"http://127.0.0.1:{port}"

    def deploy(version, mode, reset):
        r = httpx.post(base + "/_deploy", headers={"x-deploy-token": DEPLOY_TOKEN},
                       json={"version": version, "mode": mode, "reset": reset})
        assert r.status_code == 200

    data = tmp_path / "data"
    data.mkdir()
    import random

    rows = gen_data.access_logs(90, random.Random(20261119))
    (data / "j.har").write_text(json.dumps(gen_data.journeys()))
    (data / "l90.jsonl").write_text("\n".join(json.dumps(r) for r in rows))
    (data / "l30.jsonl").write_text("\n".join(json.dumps(r) for r in rows if r["ts"] >= "2026-10-20"))
    out = tmp_path / "out"
    cfg = Config(
        root=ROOT, base_url=base, har=data / "j.har", logs_30d=data / "l30.jsonl",
        logs_90d=data / "l90.jsonl",
        accounts=[Account(f"{t}_{r}", t, r, f"{e}@{t}.test", PASSWORD) for t in ("acme", "beta")
                  for r, e in (("admin", "admin"), ("agent", "agent"), ("sub_agent", "sub"))],
        out_dir=out, recordings_dir=ROOT / "demo" / "recordings", approval_wait_s=20,
        confirm_wait_s=20, poll_s=0.2, monitor_timeout_s=30)
    gw = Gateway(out_dir=out, scope_path=pol / "scope.yaml", limits_path=pol / "limits.yaml",
                 reserved_path=pol / "reserved_actions.yaml")
    orch = Orchestrator(cfg, gw, RecordedLLM(cfg.recordings_dir))
    stop = threading.Event()

    def human(confirm=True):
        book, queue, done = Rulebook(out / "rulebook.json"), ApprovalQueue(out / "approvals.json"), False
        while not stop.is_set():
            if confirm and not done and book.awaiting_confirmation():
                book.confirm_invariants("alice")
                for low in book.low_confidence_queue():
                    book.confirm_low_confidence(low, "alice")
                done = True
            for rec in queue.pending():
                try:
                    queue.approve(rec["id"], "alice")
                except KeyError:
                    pass
            time.sleep(0.02)

    yield orch, deploy, human, stop
    stop.set()
    gw.close()
    server.should_exit = True
    th.join(timeout=5)


def test_full_loop_deploy_to_auto_close(rig):
    orch, deploy, human, stop = rig
    deploy("v1.0.0", "vulnerable", True)
    threading.Thread(target=human, daemon=True).start()

    def fix():
        while orch.state != "MONITORING":
            time.sleep(0.05)
        deploy("v1.1.0", "fixed", False)

    threading.Thread(target=fix, daemon=True).start()
    assert orch.run() == "done"

    tickets = orch.tickets.all()
    assert sorted(t["invariant_id"] for t in tickets) == ["INV-01", "INV-02", "INV-03", "INV-05", "INV-08"]
    assert all(t["status"] == "Resolved" for t in tickets)
    for t in tickets:
        assert t["owner"]["team"] and t["curl"] and t["suggested_fix"] and t["impact"]
        assert [h["event"] for h in t["history"]] == ["opened", "resolved"]
    assert orch.false_positives == 0

    states = [e["state"] for e in orch.rs.data["events"]]
    for s in ("DETECTING", "MAPPING", "PROPOSING", "AWAITING_CONFIRM", "PLANNING", "CHECKING",
              "REPORTING", "MONITORING", "RETESTING", "DONE"):
        assert s in states, s
    assert states.index("AWAITING_CONFIRM") < states.index("CHECKING")  # no checks before a human confirms

    saf = orch.safety_summary()
    assert saf["out_of_scope_sent"] == 0 and saf["audit_chain_ok"] and saf["held_for_approval"] > 0
    assert orch.rs.data["scoreboard"]["deploy_to_first_proof_s"] > 0
    assert "hand-authored fixture" in orch.rs.data["llm"]["source"]
    actions = [json.loads(x) for x in orch.gw.audit.path.read_text().splitlines()
               if '"agent_action"' in x]
    assert {a["data"]["action"] for a in actions} == {"propose_invariants", "plan_checks"}
    assert all(a["data"]["prompt_version"] for a in actions)  # explainability: version logged


def test_nothing_runs_until_a_human_confirms(rig):
    orch, deploy, human, stop = rig
    orch.cfg.confirm_wait_s = 1.0
    deploy("v1.0.0", "vulnerable", True)
    assert orch.run() == "timeout"
    assert orch.checks == {} and orch.tickets.all() == []


def test_kill_switch_pauses_the_run(rig):
    orch, deploy, human, stop = rig
    deploy("v1.0.0", "vulnerable", True)
    threading.Thread(target=human, daemon=True).start()

    def kill():
        while orch.state != "CHECKING":
            time.sleep(0.01)
        orch.gw.killswitch.engage("operator pressed the kill switch")

    threading.Thread(target=kill, daemon=True).start()
    assert orch.run() == "paused"
    assert orch.state == "PAUSED_SAFETY" and orch.rs.data["safety"]["kill_switch"] is True
    assert orch.tickets.all() == [] or all(t["status"] == "Open" for t in orch.tickets.all())
