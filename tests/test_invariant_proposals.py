from pathlib import Path

import pytest

from preflight.discovery.invariants import propose_invariants, validate_candidate
from preflight.discovery.rulebook import Rulebook
from preflight.llm import LLMError, RecordedLLM
from preflight.planning.planner import plan_checks

REC = Path(__file__).resolve().parent.parent / "demo" / "recordings"
B = "/api/v1/bookings/{booking_id}"


class FakeLLM:
    name = "fake"

    def __init__(self, reply):
        self.reply, self.calls = reply, []

    def complete_json(self, task, system, payload, tier="small"):
        self.calls.append(task)
        return self.reply


def _good(**kw):
    base = {"id": "INV-01", "kind": "refund_bound", "statement": "refund never exceeds paid",
            "method": "POST", "endpoint": B + "/refunds", "params": {}, "confidence": 0.9,
            "evidence": []}
    return {**base, **kw}


# -- recorded replay ------------------------------------------------------------------------
def test_replay_serves_all_eight_invariants_and_labels_the_source(api_map_dict):
    llm = RecordedLLM(REC)
    p = propose_invariants(llm, api_map_dict)
    assert [c.id for c in p.accepted] == [f"INV-0{i}" for i in range(1, 9)]
    assert p.rejected == []
    assert "hand-authored fixture" in llm.provenance("propose_invariants")["source"]


def test_low_confidence_goes_to_the_human_queue(api_map_dict):
    p = propose_invariants(RecordedLLM(REC), api_map_dict)
    assert p.low_confidence_ids == ["INV-08"]


def test_missing_recording_is_an_error(tmp_path):
    with pytest.raises(LLMError):
        RecordedLLM(tmp_path).complete_json("propose_invariants", "", {})


def test_replay_makes_no_network_calls():
    src = (Path(__file__).resolve().parent.parent / "preflight" / "llm" / "recorded.py").read_text()
    assert "httpx" not in src and "socket" not in src


# -- validation ------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "bad,reason",
    [
        ({"kind": "tenant_isolation_read"}, "must have kind"),  # kind does not match the id
        ({"id": "INV-99"}, "not in the invariant catalogue"),
        ({"endpoint": "/api/v1/made/up"}, "not in the inferred API map"),
        ({"method": "GET"}, "not in the inferred API map"),
        ({"params": {"exfil": "x"}}, "not allowed"),
        ({"confidence": 1.5}, "schema"),
        ({"method": "TRACE"}, "schema"),
        ({"params": {"related_endpoints": ["/nope"]}, "kind": "refund_bound"}, "not allowed"),
    ],
)
def test_malformed_or_invented_proposals_are_rejected(api_map_dict, bad, reason):
    known = {(e["method"], e["path"]) for e in api_map_dict["endpoints"]}
    with pytest.raises(ValueError, match=reason):
        validate_candidate(_good(**bad), known)


def test_proposals_mix_is_filtered_not_executed(api_map_dict):
    reply = {"invariants": [_good(), _good(id="INV-02", kind="tenant_isolation_read",
                                           method="GET", endpoint=B),
                            _good(endpoint="/api/v1/ghost"), "garbage", _good()]}
    p = propose_invariants(FakeLLM(reply), api_map_dict)
    assert [c.id for c in p.accepted] == ["INV-01", "INV-02"]
    assert len(p.rejected) == 3  # ghost endpoint, non-object, duplicate


def test_reply_without_list_is_an_error(api_map_dict):
    with pytest.raises(LLMError):
        propose_invariants(FakeLLM({"nope": []}), api_map_dict)


# -- rulebook ----------------------------------------------------------------------------------
def test_rulebook_human_confirmation_flow(api_map_dict, tmp_path):
    book = Rulebook(tmp_path / "rulebook.json")
    book.propose(propose_invariants(RecordedLLM(REC), api_map_dict))
    assert len(book.awaiting_confirmation()) == 8 and book.confirmed() == []

    with pytest.raises(PermissionError):
        book.confirm_invariants("agent-1")
    assert book.confirm_invariants("alice") == [f"INV-0{i}" for i in range(1, 8)]
    assert book.low_confidence_queue() == ["INV-08"]  # still waiting for its own decision
    assert [c.id for c in book.confirmed()] == [f"INV-0{i}" for i in range(1, 8)]

    with pytest.raises(KeyError):  # normal items cannot go through the low-confidence path
        book.confirm_low_confidence("INV-01", "alice")
    book.confirm_low_confidence("INV-08", "alice")
    assert len(book.confirmed()) == 8 and book.awaiting_confirmation() == []


def test_rulebook_reject(api_map_dict, tmp_path):
    book = Rulebook(tmp_path / "r.json")
    book.propose(propose_invariants(RecordedLLM(REC), api_map_dict))
    book.reject_invariant("INV-08", "alice")
    book.confirm_invariants("alice")
    assert "INV-08" not in [c.id for c in book.confirmed()]


# -- planner -----------------------------------------------------------------------------------
def _confirmed(api_map_dict, tmp_path):
    book = Rulebook(tmp_path / "r.json")
    book.propose(propose_invariants(RecordedLLM(REC), api_map_dict))
    book.confirm_invariants("alice")
    book.confirm_low_confidence("INV-08", "alice")
    return book.confirmed()


def test_one_plan_per_confirmed_invariant(api_map_dict, tmp_path):
    confirmed = _confirmed(api_map_dict, tmp_path)
    res = plan_checks(RecordedLLM(REC), confirmed)
    assert sorted(p.invariant_id for p in res.plans) == sorted(c.id for c in confirmed)
    assert res.rejected == [] and res.unplanned == []


def test_no_invariant_no_plan(api_map_dict, tmp_path):
    confirmed = _confirmed(api_map_dict, tmp_path)[:3]  # INV-04..08 are not confirmed
    res = plan_checks(RecordedLLM(REC), confirmed)
    assert [p.invariant_id for p in res.plans] == ["INV-01", "INV-02", "INV-03"]
    assert len(res.rejected) == 5 and "not a confirmed invariant" in res.rejected[0]["reason"]


def test_plan_must_match_its_invariant(api_map_dict, tmp_path):
    confirmed = _confirmed(api_map_dict, tmp_path)[:1]
    plan = {"invariant_id": "INV-01", "check": "refund_bound", "method": "POST",
            "endpoint": B + "/pay", "params": {}}
    res = plan_checks(FakeLLM({"plans": [plan, {**plan, "endpoint": B + "/refunds"}]}), confirmed)
    assert len(res.plans) == 1 and "must use the invariant's kind" in res.rejected[0]["reason"]
    res2 = plan_checks(FakeLLM({"plans": []}), confirmed)
    assert res2.unplanned == ["INV-01"]
