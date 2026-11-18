"""In-memory world for the synthetic target: tenants, users, customers, bookings, hotels.

All data is fake: .test e-mail domains, invented names, made-up passport numbers.
"""

from __future__ import annotations

import hashlib
import sqlite3
import threading
from dataclasses import dataclass

PASSWORD = "Test-Pass-1!"  # shared by every synthetic account
SUPPLIER_SECRET = b"synthetic-supplier-webhook-key"
DEPLOY_TOKEN = "synthetic-deploy-token"
ROLES = ("admin", "agent", "sub_agent")

TENANTS = {
    "T1": {"name": "Acme Travels", "markup_pct": 8.0},
    "T2": {"name": "Beta Voyages", "markup_pct": 6.0},
}

HOTELS = [
    (1, "Goa", "Palm Cove Resort", 6200.0, 4.4),
    (2, "Goa", "Sunset Bay Hotel", 4100.0, 4.0),
    (3, "Goa", "Old Quarter Inn", 2300.0, 3.6),
    (4, "Jaipur", "Rambagh Heritage", 9800.0, 4.8),
    (5, "Jaipur", "Pink City Suites", 3900.0, 4.1),
    (6, "Jaipur", "Amber Gate Lodge", 2100.0, 3.5),
    (7, "Kochi", "Backwater Grand", 5400.0, 4.3),
    (8, "Kochi", "Fort Lane Homestay", 1900.0, 3.8),
    (9, "Dubai", "Marina Skyline", 14500.0, 4.6),
    (10, "Dubai", "Creek Side Hotel", 7800.0, 4.0),
    (11, "Singapore", "Harbour View", 16200.0, 4.5),
    (12, "Singapore", "Little India Stay", 6900.0, 3.9),
]


def pw_hash(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


@dataclass
class User:
    id: str
    email: str
    name: str
    tenant_id: str
    role: str
    phone: str = ""


class World:
    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.users: dict[str, User] = {}
        for uid, email, name, tenant, role in [
            ("u1", "admin@acme.test", "Asha Admin", "T1", "admin"),
            ("u2", "agent@acme.test", "Arjun Agent", "T1", "agent"),
            ("u3", "sub@acme.test", "Sana Sub", "T1", "sub_agent"),
            ("u4", "admin@beta.test", "Bela Admin", "T2", "admin"),
            ("u5", "agent@beta.test", "Bharat Agent", "T2", "agent"),
            ("u6", "sub@beta.test", "Bina Sub", "T2", "sub_agent"),
        ]:
            self.users[uid] = User(uid, email, name, tenant, role, "+91-00000-0000" + uid[1])
        self.tokens: dict[str, tuple[str, float]] = {}
        self.failed_logins: dict[str, tuple[int, float]] = {}
        self.customers: dict[str, dict] = {
            "C1": dict(id="C1", tenant_id="T1", name="Ravi Kumar", email="ravi@cust.test",
                       phone="+91-11111-0001", passport_no="ZX1234501", dob="1985-03-14"),
            "C2": dict(id="C2", tenant_id="T1", name="Meera Shah", email="meera@cust.test",
                       phone="+91-11111-0002", passport_no="ZX1234502", dob="1990-07-02"),
            "C3": dict(id="C3", tenant_id="T2", name="Tom Becker", email="tom@cust.test",
                       phone="+44-22222-0003", passport_no="ZX9876503", dob="1979-11-23"),
            "C4": dict(id="C4", tenant_id="T2", name="Lina Park", email="lina@cust.test",
                       phone="+82-22222-0004", passport_no="ZX9876504", dob="1995-01-30"),
        }
        self.holds: dict[str, dict] = {}
        self.bookings: dict[str, dict] = {}
        self.invoices: dict[str, dict] = {}
        self.refunds: list[dict] = []
        self._seq = {"booking": 3000, "hold": 0, "customer": 100, "ticket": 0, "refund": 0}
        self._seed_bookings()
        self.db = self._build_db()
        self.db_lock = threading.Lock()

    def next(self, kind: str) -> int:
        self._seq[kind] += 1
        return self._seq[kind]

    def _seed_bookings(self) -> None:
        for bid, tenant, cust, user, hotel, status, total in [
            ("BK-1001", "T1", "C1", "u2", "Palm Cove Resort", "pending_payment", 26784.0),
            ("BK-1002", "T1", "C2", "u2", "Rambagh Heritage", "paid", 21168.0),
            ("BK-2001", "T2", "C3", "u5", "Backwater Grand", "pending_payment", 11448.0),
            ("BK-2002", "T2", "C4", "u5", "Marina Skyline", "paid", 30740.0),
        ]:
            paid = total if status == "paid" else 0.0
            self.bookings[bid] = dict(
                id=bid, tenant_id=tenant, customer_id=cust, created_by=user, hotel=hotel,
                nights=2, pax=2, currency="INR", status=status, total_amount=total,
                amount_paid=paid, refunded_total=0.0, supplier_cost=round(total / 1.08, 2),
                ticket_no=None, supplier_status="unconfirmed",
            )
            if status == "paid":
                self.invoices["INV-" + bid[3:]] = dict(
                    id="INV-" + bid[3:], booking_id=bid, tenant_id=tenant, amount=total,
                    customer=self.customers[cust]["name"], issued="2026-10-20",
                )

    @staticmethod
    def _build_db() -> sqlite3.Connection:
        db = sqlite3.connect(":memory:", check_same_thread=False)
        db.execute("CREATE TABLE hotels(id INTEGER, city TEXT, name TEXT, rate REAL, rating REAL)")
        db.executemany("INSERT INTO hotels VALUES (?,?,?,?,?)", HOTELS)
        db.execute("CREATE TABLE internal_notes(id INTEGER, note TEXT)")
        db.execute("INSERT INTO internal_notes VALUES (1, 'SYNTH-SUPPLIER-KEY-0000-FAKE')")
        db.execute("INSERT INTO internal_notes VALUES (2, 'synthetic negotiated-rate memo')")
        db.commit()
        return db


world = World()
