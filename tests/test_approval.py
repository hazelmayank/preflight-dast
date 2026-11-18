import pytest

from preflight.safety.approval import ApprovalQueue, ReservedActions


def test_reserved_matching(policy):
    r = ReservedActions.from_file(policy / "reserved_actions.yaml")
    assert r.match("POST", "/api/v1/bookings/BK-1/pay") == "payment"
    assert r.match("POST", "/api/v1/bookings/BK-1/cancel") == "cancellation"
    assert r.match("POST", "/api/v1/bookings/BK-1/refunds") == "refund"
    assert r.match("PATCH", "/api/v1/users/u2") == "role_change"
    assert r.match("POST", "/webhooks/supplier") == "supplier_callback"
    assert r.match("GET", "/api/v1/bookings/BK-1/pay") is None
    assert r.match("GET", "/api/v1/search") is None
    assert r.match("POST", "/api/v1/holds") is None


def _q(tmp_path, now=lambda: 1000.0):
    return ApprovalQueue(tmp_path / "a.json", ttl_s=100, wall_clock=now)


def test_flow_single_use_and_fingerprint_bound(tmp_path):
    q = _q(tmp_path)
    fp = ApprovalQueue.fingerprint("POST", "http://127.0.0.1:8000/x/pay", None, b"{}")
    rec = q.request("payment", "POST", "u", fp, "agent", "t")
    assert not q.is_approved(rec["id"], fp)
    assert q.request("payment", "POST", "u", fp, "agent", "t")["id"] == rec["id"]  # de-duped
    q.approve(rec["id"], "alice")
    assert q.is_approved(rec["id"], fp)
    other = ApprovalQueue.fingerprint("POST", "http://127.0.0.1:8000/x/pay", None, b'{"a":1}')
    assert not q.is_approved(rec["id"], other)
    q.consume(rec["id"])
    assert not q.is_approved(rec["id"], fp)


def test_agent_like_names_cannot_approve(tmp_path):
    q = _q(tmp_path)
    rec = q.request("refund", "POST", "u", "fp", "agent", "")
    for who in ("", "agent-1", "Preflight", "auto"):
        with pytest.raises(PermissionError):
            q.approve(rec["id"], who)


def test_approval_expires(tmp_path):
    t = [1000.0]
    q = _q(tmp_path, lambda: t[0])
    rec = q.request("refund", "POST", "u", "fp", "agent", "")
    q.approve(rec["id"], "alice")
    t[0] += 500
    assert not q.is_approved(rec["id"], "fp")
