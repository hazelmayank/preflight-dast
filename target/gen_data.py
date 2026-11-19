"""Generate synthetic traffic for the target: 30/90-day access logs and a HAR of normal journeys.

Output (git-ignored) goes to ``target/data/``. Deterministic: same seed, same files. Fake data only.
Run: ``python -m target.gen_data``.

Shape of the logs (what inventory should later discover):
* active: the /api/v1 routes, steady traffic through the last 30 days;
* zombie: /api/v0/bookings/{id}, traffic only 35-90 days ago, nothing since;
* shadow: /internal/debug/config and the supplier webhook, rare and from internal callers,
  never referenced by the front-end bundle.
"""

from __future__ import annotations

import json
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi.testclient import TestClient

from . import bugs
from .app import app
from .store import DEPLOY_TOKEN, PASSWORD

OUT = Path(__file__).resolve().parent / "data"
ANCHOR = datetime(2026, 11, 19, tzinfo=UTC)

# (method, path template, weight, roles that call it)
ACTIVE = [
    ("POST", "/api/v1/auth/login", 10, ("admin", "agent", "sub_agent")),
    ("GET", "/api/v1/me", 8, ("admin", "agent", "sub_agent")),
    ("GET", "/api/v1/search", 30, ("admin", "agent", "sub_agent")),
    ("POST", "/api/v1/holds", 12, ("agent", "sub_agent")),
    ("POST", "/api/v1/bookings", 8, ("agent", "admin")),
    ("GET", "/api/v1/bookings", 9, ("admin", "agent", "sub_agent")),
    ("GET", "/api/v1/bookings/{booking}", 14, ("admin", "agent", "sub_agent")),
    ("POST", "/api/v1/bookings/{booking}/pay", 6, ("agent", "admin")),
    ("POST", "/api/v1/bookings/{booking}/cancel", 2, ("agent", "admin")),
    ("POST", "/api/v1/bookings/{booking}/refunds", 1, ("admin",)),
    ("POST", "/api/v1/bookings/{booking}/ticket", 5, ("agent", "admin")),
    ("GET", "/api/v1/invoices/{invoice}", 4, ("agent", "admin")),
    ("GET", "/api/v1/customers/{customer}", 4, ("agent", "admin", "sub_agent")),
    ("GET", "/api/v1/users", 1, ("admin",)),
    ("PATCH", "/api/v1/users/{user}", 1, ("admin",)),
    ("POST", "/api/v1/auth/logout", 5, ("admin", "agent", "sub_agent")),
    ("POST", "/api/v1/suppliers/test-connection", 0.2, ("admin",)),
]


def _fill(template: str, rnd: random.Random) -> str:
    return (template.replace("{booking}", f"BK-{rnd.choice([1001, 1002, 2001, 2002, 3001, 3002])}")
            .replace("{invoice}", f"INV-{rnd.choice([1002, 2002, 3001])}")
            .replace("{customer}", f"C{rnd.randint(1, 4)}")
            .replace("{user}", f"u{rnd.randint(1, 6)}"))


def _line(ts: datetime, method: str, path: str, role: str, rnd: random.Random, source: str) -> dict:
    tenant = rnd.choice(["T1", "T2"])
    status = rnd.choices([200, 201, 400, 401, 403, 404, 409], [80, 4, 3, 3, 3, 4, 3])[0]
    return {"ts": ts.isoformat().replace("+00:00", "Z"), "method": method, "path": path,
            "status": status, "latency_ms": round(rnd.lognormvariate(4.2, 0.5), 1),
            "tenant": tenant, "role": role, "user": f"u{rnd.randint(1, 6)}", "source": source}


def access_logs(days: int, rnd: random.Random) -> list[dict]:
    rows: list[dict] = []
    weights = [w for _, _, w, _ in ACTIVE]
    for d in range(days):
        day = ANCHOR - timedelta(days=d)
        for _ in range(rnd.randint(80, 120)):  # ~100 calls/day on active routes
            method, tmpl, _, roles = rnd.choices(ACTIVE, weights)[0]
            ts = day.replace(hour=rnd.randint(4, 17), minute=rnd.randint(0, 59),
                             second=rnd.randint(0, 59))
            rows.append(_line(ts, method, _fill(tmpl, rnd), rnd.choice(roles), rnd, "partner-ip"))
        if 35 <= d < 90 and d % 4 == 0:  # zombie: only in older months
            ts = day.replace(hour=rnd.randint(4, 17), minute=rnd.randint(0, 59), second=0)
            rows.append(_line(ts, "GET", f"/api/v0/bookings/BK-{rnd.choice([1001, 1002])}",
                              "agent", rnd, "legacy-integration"))
        if d % 6 == 0:  # shadow: internal tooling, never in the front-end
            ts = day.replace(hour=rnd.randint(0, 3), minute=rnd.randint(0, 59), second=0)
            rows.append(_line(ts, "GET", "/internal/debug/config", "admin", rnd, "internal-tool"))
        if d % 3 == 0:
            ts = day.replace(hour=rnd.randint(0, 23), minute=rnd.randint(0, 59), second=0)
            rows.append(_line(ts, "POST", "/webhooks/supplier", "agent", rnd, "supplier-ip"))
    rows.sort(key=lambda r: r["ts"])
    return rows


class Recorder:
    """Drives the target in-process and records each exchange as a HAR entry."""

    def __init__(self, client: TestClient):
        self.client, self.entries = client, []
        self.t = ANCHOR - timedelta(hours=2)

    def call(self, method: str, path: str, token: str | None = None, **kw):
        headers = {"authorization": f"Bearer {token}"} if token else {}
        resp = self.client.request(method, path, headers=headers, **kw)
        body = kw.get("json")
        self.entries.append({
            "startedDateTime": self.t.isoformat().replace("+00:00", "Z"),
            "time": 12,
            "request": {
                "method": method, "url": f"http://127.0.0.1:8000{path}", "httpVersion": "HTTP/1.1",
                "headers": [{"name": "Authorization", "value": "Bearer <redacted>"}] if token else [],
                "queryString": [{"name": k, "value": str(v)}
                                for k, v in (kw.get("params") or {}).items()],
                "postData": {"mimeType": "application/json", "text": json.dumps(body)} if body else None,
            },
            "response": {"status": resp.status_code, "headers": [],
                         "content": {"mimeType": "application/json", "text": resp.text}},
        })
        self.t += timedelta(seconds=7)
        return resp


def journeys() -> dict:
    """HAR of normal use by each role in both tenants, recorded against the fixed build."""
    with TestClient(app) as client:
        client.post("/_deploy", headers={"x-deploy-token": DEPLOY_TOKEN},
                    json={"version": "har-baseline", "mode": "fixed", "reset": True})
        rec = Recorder(client)

        def login(email: str) -> str:
            return rec.call("POST", "/api/v1/auth/login",
                            json={"email": email, "password": PASSWORD}).json()["token"]

        for tenant, cust in (("acme", "C1"), ("beta", "C3")):
            agent = login(f"agent@{tenant}.test")
            rec.call("GET", "/api/v1/me", agent)
            offers = rec.call("GET", "/api/v1/search", agent, params={"city": "Goa"}).json()["offers"]
            hold = rec.call("POST", "/api/v1/holds", agent,
                            json={"offer_id": offers[0]["offer_id"], "nights": 2, "pax": 2}).json()
            booking = rec.call("POST", "/api/v1/bookings", agent,
                               json={"hold_id": hold["hold_id"], "customer_id": cust}).json()
            rec.call("GET", f"/api/v1/bookings/{booking['id']}", agent)
            rec.call("POST", f"/api/v1/bookings/{booking['id']}/pay", agent,
                     json={"amount": booking["total_amount"]})
            rec.call("GET", f"/api/v1/invoices/INV-{booking['id'][3:]}", agent)
            rec.call("GET", f"/api/v1/customers/{cust}", agent)
            rec.call("POST", f"/api/v1/bookings/{booking['id']}/ticket", agent)

            # second booking: paid, then cancelled and refunded by the admin (cancel before refund)
            hold2 = rec.call("POST", "/api/v1/holds", agent,
                             json={"offer_id": offers[1]["offer_id"], "nights": 1, "pax": 1}).json()
            b2 = rec.call("POST", "/api/v1/bookings", agent,
                          json={"hold_id": hold2["hold_id"], "customer_id": cust}).json()
            rec.call("POST", f"/api/v1/bookings/{b2['id']}/pay", agent,
                     json={"amount": b2["total_amount"]})

            admin = login(f"admin@{tenant}.test")
            rec.call("GET", "/api/v1/users", admin)
            rec.call("GET", "/api/v1/bookings", admin)
            rec.call("POST", f"/api/v1/bookings/{b2['id']}/cancel", admin)
            rec.call("POST", f"/api/v1/bookings/{b2['id']}/refunds", admin,
                     json={"amount": b2["total_amount"], "reason": "customer request"})
            rec.call("POST", "/api/v1/auth/logout", admin)

            sub = login(f"sub@{tenant}.test")
            rec.call("GET", "/api/v1/search", sub, params={"city": "Jaipur"})
            sub_hold = rec.call("POST", "/api/v1/holds", sub,
                                json={"offer_id": 4, "nights": 1, "pax": 1})
            rec.call("GET", "/api/v1/bookings", sub)
            assert sub_hold.status_code == 200
        entries = rec.entries
        client.post("/_deploy", headers={"x-deploy-token": DEPLOY_TOKEN},
                    json={"version": "v1.0.0", "mode": "vulnerable", "reset": True})
    bugs.state.deploys = 0
    return {"log": {"version": "1.2", "creator": {"name": "synthetic-recorder", "version": "1"},
                    "entries": entries}}


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    rnd = random.Random(20261119)
    full = access_logs(90, rnd)
    cutoff = (ANCHOR - timedelta(days=30)).isoformat().replace("+00:00", "Z")
    recent = [r for r in full if r["ts"] >= cutoff]
    for name, rows in (("access_30d.jsonl", recent), ("access_90d.jsonl", full)):
        (OUT / name).write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    (OUT / "journeys.har").write_text(json.dumps(journeys(), indent=1), encoding="utf-8")
    print(f"wrote {len(recent)} (30d) and {len(full)} (90d) log lines and journeys.har to {OUT}")


if __name__ == "__main__":
    main()
