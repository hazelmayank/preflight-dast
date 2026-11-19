import json

import pytest
from fastapi.testclient import TestClient

from bench.score import SEED_MAP, score, write_report
from preflight.discovery.invariants import propose_invariants
from preflight.discovery.rulebook import Rulebook
from preflight.llm import RecordedLLM
from preflight.safety.approval import ApprovalQueue
from preflight.ui.server import app
from tests.test_invariant_proposals import REC


@pytest.fixture
def ui(tmp_path, monkeypatch, api_map_dict):
    monkeypatch.setenv("PREFLIGHT_OUT", str(tmp_path))
    return TestClient(app), tmp_path


def test_state_and_human_actions(ui, api_map_dict):
    client, out = ui
    assert client.get("/").status_code == 200 and b"Preflight control room" in client.get("/").content
    book = Rulebook(out / "rulebook.json")
    book.propose(propose_invariants(RecordedLLM(REC), api_map_dict))
    q = ApprovalQueue(out / "approvals.json")
    rec = q.request("refund", "POST", "http://127.0.0.1:8000/x/refunds", "fp", "agent", "t")

    s = client.get("/api/state").json()
    assert len(s["awaiting_confirmation"]) == 8 and s["low_confidence"] == ["INV-08"]
    assert s["pending_approvals"][0]["id"] == rec["id"]

    assert client.post(f"/api/approvals/{rec['id']}/approve", json={"by": ""}).status_code == 422
    assert client.post(f"/api/approvals/{rec['id']}/approve", json={"by": "agent-7"}).status_code == 400
    assert client.post(f"/api/approvals/{rec['id']}/approve", json={"by": "alice"}).status_code == 200
    assert q.is_approved(rec["id"], "fp")

    assert client.post("/api/invariants/confirm", json={"by": "alice"}).json()["confirmed"][0] == "INV-01"
    assert client.post("/api/invariants/INV-08/confirm", json={"by": "alice"}).status_code == 200
    assert client.get("/api/state").json()["awaiting_confirmation"] == []

    client.post("/api/kill", json={"by": "alice"})
    assert (out / "KILL").exists()


def test_scorer_matches_tickets_to_seeds(tmp_path):
    seeds = tmp_path / "seeds.yaml"
    seeds.write_text("seeds:\n" + "\n".join(
        f"  - {{id: S{i:02d}, class: {'injection' if i == 12 else 'access_control'}, title: t{i}}}"
        for i in range(1, 21)))
    (tmp_path / "tickets.json").write_text(json.dumps(
        [{"id": "FIND-INV-01", "invariant_id": "INV-01"}, {"id": "FIND-INV-08", "invariant_id": "INV-08"},
         {"id": "FIND-INV-99", "invariant_id": "INV-99"}]))
    (tmp_path / "state.json").write_text(json.dumps({"scoreboard": {"findings": 3, "resolved": 3,
                                                                      "false_positives_clean_build": 0}}))
    r = score(tmp_path, seeds)
    assert r["found_ids"] == ["S08", "S15", "S17"] and r["found"] == 3 and r["total"] == 20
    assert r["unmatched_findings"] == ["FIND-INV-99"] and round(r["precision"], 2) == 0.67
    assert any(m["id"] == "S12" and "out of MVP" in m["reason"] for m in r["misses"])
    assert set(SEED_MAP) == {"INV-01", "INV-02", "INV-03", "INV-05", "INV-08"}
    report = tmp_path / "B.md"
    write_report(r, report)
    text = report.read_text()
    assert "Not blind" in text and "S12" in text


def test_scorer_degrades_gracefully_without_the_private_ground_truth(tmp_path):
    (tmp_path / "tickets.json").write_text(json.dumps([{"id": "FIND-INV-01", "invariant_id": "INV-01"}]))
    r = score(tmp_path, tmp_path / "missing" / "seeds.yaml")
    assert r["ground_truth"] is False and r["total"] is None and r["found_ids"] == ["S08"]
    with pytest.raises(ValueError):
        write_report(r, tmp_path / "B.md")
    assert not (tmp_path / "B.md").exists()
