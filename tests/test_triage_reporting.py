import time

import pytest

from preflight.discovery.invariant_schema import CheckPlan
from preflight.execution.verifier import Finding
from preflight.reporting.tickets import TicketStore
from preflight.triage.triage import dedupe, impact_text, owner_for, severity, triage


def finding(kind="refund_bound", inv="INV-01", endpoint="/api/v1/bookings/{booking_id}/refunds",
            method="POST", t=None, **impact):
    ev = {"label": "variation", "actor": "a", "method": method, "path": "/x", "url": "http://127.0.0.1:8000/x",
          "status": 200, "request_body": {"amount": 2}, "approval_id": None, "response": "{}"}
    return Finding(inv, kind, method, endpoint, [ev, ev], [ev], 2, impact, "curl -s -X POST 'u'",
                   detected_at=t or time.time())


def test_severity_by_business_impact():
    assert severity(finding(money_delta_inr=20000))[0] == "critical"
    assert severity(finding("price_integrity", "INV-04", money_delta_inr=20000))[0] == "critical"
    assert severity(finding("price_integrity", "INV-04", money_delta_inr=100))[0] == "high"
    assert severity(finding("tenant_isolation_read", cross_tenant=True))[0] == "high"
    exposed = finding("no_sensitive_exposure", data_exposure=True, fields=["customer.dob"])
    assert severity(exposed)[0] == "medium"
    sev, why = severity(finding("no_sensitive_exposure", data_exposure=True, fields=["jwt_secret"]))
    assert sev == "high" and any("secrets" in w for w in why)


def test_impact_text_labels_assumptions():
    t = impact_text(finding(money_delta_inr=5000))
    assert "5,000" in t and "assumption" in t


def test_owner_lookup():
    assert owner_for("/api/v1/bookings/{booking_id}/refunds")["team"] == "payments-team"
    assert owner_for("/api/v1/admin/tenants/{tenant_id}/users")["team"] == "identity-and-access"
    assert owner_for("/internal/debug/config")["team"] == "platform-sre"
    assert owner_for("/api/v1/bookings/{booking_id}")["team"] == "bookings-team"
    assert owner_for("/something/else")["team"] == "platform-engineering"


def test_dedupe_keeps_earliest_per_key():
    a, b = finding(t=1.0), finding(t=2.0)
    c = finding("no_double_refund", "INV-05", t=3.0)
    out = dedupe([b, a, c])
    assert len(out) == 2 and out[0].detected_at == 1.0


def _plan():
    return CheckPlan(invariant_id="INV-01", check="refund_bound", method="POST",
                     endpoint="/api/v1/bookings/{booking_id}/refunds")


def test_ticket_contents_dedupe_and_history(tmp_path):
    store = TicketStore(tmp_path)
    tri = triage([finding(money_delta_inr=20000)])[0]
    t = store.file(tri, _plan(), "v1.0.0", 12.3)
    assert t["id"] == "FIND-INV-01" and t["status"] == "Open" and t["severity"] == "critical"
    for key in ("owner", "evidence", "curl", "suggested_fix", "impact", "history", "plan"):
        assert t[key]
    again = store.file(tri, _plan(), "v1.0.0", 5.0)  # same finding: no second ticket
    assert len(store.all()) == 1 and again["history"][-1]["event"] == "seen again"
    store.add_history("FIND-INV-01", "resolved", "ok", status="Resolved")
    assert store.open_tickets() == []
    md = (tmp_path / "tickets" / "FIND-INV-01.md").read_text()
    assert "Suggested fix" in md and "History" in md and "payments-team" in md
    with pytest.raises(KeyError):
        store.get("nope")
