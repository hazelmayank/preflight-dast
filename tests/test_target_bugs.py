"""Every seeded bug is exploitable in vulnerable mode and blocked in fixed mode."""

import hashlib
import hmac

import pytest
from fastapi.testclient import TestClient

from target import bugs
from target.app import app
from target.store import DEPLOY_TOKEN, PASSWORD, SUPPLIER_SECRET


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def deploy(c, mode, patched=()):
    r = c.post("/_deploy", headers={"x-deploy-token": DEPLOY_TOKEN},
               json={"version": "t", "mode": mode, "patched": list(patched), "reset": True})
    assert r.status_code == 200


def login(c, email, password=PASSWORD):
    r = c.post("/api/v1/auth/login", json={"email": email, "password": password})
    return r, ({"authorization": "Bearer " + r.json()["token"]} if r.status_code == 200 else {})


def H(c, who):
    return login(c, f"{who}@acme.test")[1]


def new_booking(c, h, pax=1, **extra):
    hold = c.post("/api/v1/holds", headers=h, json={"offer_id": 1, "nights": 1, "pax": pax})
    if hold.status_code != 200:
        return None
    r = c.post("/api/v1/bookings", headers=h,
               json={"hold_id": hold.json()["hold_id"], "customer_id": "C1", **extra})
    return r.json() if r.status_code == 200 else None


def paid_booking(c):
    h = H(c, "agent")
    b = new_booking(c, h)
    c.post(f"/api/v1/bookings/{b['id']}/pay", headers=h, json={"amount": b["total_amount"]})
    return b, h


# Each exploit returns True when the vulnerability is present.
def s01(c):  # agent of tenant 1 reads a tenant-2 booking
    return c.get("/api/v1/bookings/BK-2001", headers=H(c, "agent")).status_code == 200


def s02(c):
    return c.get("/api/v1/invoices/INV-2002", headers=H(c, "agent")).status_code == 200


def s03(c):
    h = H(c, "agent")
    r = c.patch("/api/v1/users/u2", headers=h, json={"role": "admin"})
    return r.status_code == 200 and r.json()["role"] == "admin"


def s04(c):
    r = c.get("/api/v1/admin/tenants/T2/users", headers=H(c, "sub"))
    return r.status_code == 200


def s05(c):
    b = new_booking(c, H(c, "agent"), total_amount=1.0)
    return b is not None and b["total_amount"] == 1.0


def s06(c):
    b = new_booking(c, H(c, "agent"), markup_pct=-90.0)
    return bool(b) and "supplier_cost" in b and b["total_amount"] < b["supplier_cost"]


def s07(c):
    h = H(c, "agent")
    r = c.post("/api/v1/holds", headers=h, json={"offer_id": 1, "nights": 1, "pax": -2})
    return r.status_code == 200 and r.json()["total_amount"] < 0


def s08(c):
    b, _ = paid_booking(c)
    a = H(c, "admin")
    c.post(f"/api/v1/bookings/{b['id']}/cancel", headers=a)
    r = c.post(f"/api/v1/bookings/{b['id']}/refunds", headers=a,
               json={"amount": b["total_amount"] * 10})
    return r.status_code == 200


def s09(c):
    b, _ = paid_booking(c)
    a = H(c, "admin")
    c.post(f"/api/v1/bookings/{b['id']}/cancel", headers=a)
    url = f"/api/v1/bookings/{b['id']}/refunds"
    c.post(url, headers=a, json={"amount": b["total_amount"]})
    return c.post(url, headers=a, json={"amount": b["total_amount"]}).status_code == 200


def s10(c):
    h = H(c, "agent")
    b = new_booking(c, h)
    return c.post(f"/api/v1/bookings/{b['id']}/ticket", headers=h).status_code == 200


def s11(c):
    b, _ = paid_booking(c)
    r = c.post(f"/api/v1/bookings/{b['id']}/refunds", headers=H(c, "admin"),
               json={"amount": 1.0})
    return r.status_code == 200


def s12(c):
    r = c.get("/api/v1/search", headers=H(c, "sub"),
              params={"city": "x' UNION SELECT id, note, note, 0, 0 FROM internal_notes--"})
    return r.status_code == 200 and "SYNTH-SUPPLIER-KEY" in r.text


def s13(c):
    r = c.post("/api/v1/suppliers/test-connection", headers=H(c, "admin"),
               json={"url": "http://169.254.169.254/latest/meta-data/"})
    return r.status_code == 200 and "SYNTH-METADATA" in r.text


def s14(c):
    r = c.post("/webhooks/supplier", json={"booking_id": "BK-1001", "supplier_status": "confirmed"})
    return r.status_code == 200


def s15(c):
    r = c.get("/api/v1/bookings/BK-1001", headers=H(c, "agent"))
    return "internal_margin" in r.json() or "dob" in r.json()["customer"]


def s16(c):
    return c.get("/api/v0/bookings/BK-1001").status_code == 200


def s17(c):
    return c.get("/internal/debug/config").status_code == 200


def s18(c):
    r = login(c, "nobody@acme.test")[0]
    return "unknown user" in r.text


def s19(c):
    h = H(c, "agent")
    c.post("/api/v1/auth/logout", headers=h)
    return c.get("/api/v1/me", headers=h).status_code == 200


def s20(c):
    r = c.get("/api/v1/invoices/garbage", headers=H(c, "agent"))
    return "Traceback" in r.text


EXPLOITS = {f"S{i:02d}": globals()[f"s{i:02d}"] for i in range(1, 21)}


def test_every_bug_has_an_exploit():
    assert set(EXPLOITS) == set(bugs.BUG_IDS)


@pytest.mark.parametrize("bug", bugs.BUG_IDS)
def test_vulnerable_mode_is_exploitable(client, bug):
    deploy(client, "vulnerable")
    assert EXPLOITS[bug](client) is True


@pytest.mark.parametrize("bug", bugs.BUG_IDS)
def test_fixed_mode_blocks_exploit(client, bug):
    deploy(client, "fixed")
    assert EXPLOITS[bug](client) is False


def test_partial_patch_fixes_only_listed_bugs(client):
    deploy(client, "vulnerable", patched=["S01"])
    assert s01(client) is False and s02(client) is True


def test_signed_webhook_accepted_in_fixed_mode(client):
    deploy(client, "fixed")
    raw = b'{"booking_id": "BK-1001", "supplier_status": "failed"}'
    sig = hmac.new(SUPPLIER_SECRET, raw, hashlib.sha256).hexdigest()
    r = client.post("/webhooks/supplier", content=raw, headers={"x-supplier-signature": sig})
    assert r.status_code == 200


def test_fixed_mode_lockout_after_failures(client):
    deploy(client, "fixed")
    for _ in range(5):
        login(client, "agent@acme.test", "wrong")
    assert login(client, "agent@acme.test")[0].status_code == 429


def test_roles_and_happy_path_work_in_fixed_mode(client):
    deploy(client, "fixed")
    h = H(client, "agent")
    b = new_booking(client, h)
    assert b and b["status"] == "pending_payment"
    assert client.post(f"/api/v1/bookings/{b['id']}/pay", headers=h,
                       json={"amount": b["total_amount"]}).json()["status"] == "paid"
    assert client.post(f"/api/v1/bookings/{b['id']}/ticket", headers=h).status_code == 200
    assert client.post("/api/v1/holds", headers=H(client, "sub"),
                       json={"offer_id": 1}).status_code == 200
    assert client.get("/api/v1/users", headers=H(client, "agent")).status_code == 403


def test_version_endpoint_does_not_reveal_mode(client):
    deploy(client, "vulnerable")
    assert set(client.get("/_version").json()) == {"version"}
