"""Waypoint-lite: a synthetic B2B travel API with seeded, switchable vulnerabilities.

Run: ``uvicorn target.app:app --port 8000``. Every bug is guarded by ``vulnerable("Sxx")`` so a
deploy (``POST /_deploy``) flips the build between vulnerable and fixed. All data is fake and
nothing here touches the real network.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import traceback
import uuid
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field

from . import bugs
from .bugs import vulnerable
from .store import DEPLOY_TOKEN, PASSWORD, ROLES, SUPPLIER_SECRET, TENANTS, User, world

app = FastAPI(title="Waypoint-lite (synthetic)", docs_url=None, redoc_url=None, openapi_url=None)
TOKEN_TTL_S = 3600
LOCKOUT_AFTER = 5


# ---------------------------------------------------------------------------- error handling
@app.middleware("http")
async def catch_errors(request: Request, call_next):
    try:
        return await call_next(request)
    except Exception as exc:  # noqa: BLE001 - this is the app's last-resort handler
        if vulnerable("S20"):  # S20: stack traces and internals leak to the client
            return JSONResponse(
                {"error": repr(exc), "trace": traceback.format_exc(), "db": "sqlite:///:memory:"},
                status_code=500,
            )
        return JSONResponse({"error": "internal error"}, status_code=500)


# ---------------------------------------------------------------------------------- models
class LoginIn(BaseModel):
    email: str
    password: str


class HoldIn(BaseModel):
    offer_id: int
    nights: int = Field(default=1, ge=1, le=30)
    pax: int = 1


class CustomerIn(BaseModel):
    name: str
    email: str
    passport_no: str = ""


class BookingIn(BaseModel):
    hold_id: str
    customer_id: str | None = None
    customer: CustomerIn | None = None
    total_amount: float | None = None  # S05 (client-supplied price)
    markup_pct: float | None = None  # S06 (client-supplied markup)


class PayIn(BaseModel):
    amount: float
    method: str = "card"
    card_token: str = "tok_test_visa"


class RefundIn(BaseModel):
    amount: float
    reason: str = ""


class UserPatch(BaseModel):
    name: str | None = None
    phone: str | None = None
    role: str | None = None  # S03 (mass assignment)


class ConnIn(BaseModel):
    url: str


class DeployIn(BaseModel):
    version: str
    mode: str
    patched: list[str] = []
    reset: bool = False


# ---------------------------------------------------------------------------------- helpers
def fail(code: int, msg: str):
    raise HTTPException(code, msg)


def current_user(request: Request) -> User:
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        fail(401, "missing bearer token")
    entry = world.tokens.get(header[7:].strip())
    if not entry or entry[1] < time.time():
        fail(401, "invalid or expired token")
    return world.users[entry[0]]


def need_role(user: User, *roles: str) -> None:
    if user.role not in roles:
        fail(403, "role not permitted")


def tenant_booking(bid: str, user: User) -> dict:
    """A booking the caller may act on: same tenant (and own bookings for sub-agents)."""
    b = world.bookings.get(bid)
    if not b or b["tenant_id"] != user.tenant_id:
        fail(404, "booking not found")
    if user.role == "sub_agent" and b["created_by"] != user.id:
        fail(404, "booking not found")
    return b


def mask_passport(p: str) -> str:
    return "*" * max(0, len(p) - 3) + p[-3:]


def public_booking(b: dict, user: User) -> dict:
    out = {k: b[k] for k in (
        "id", "tenant_id", "status", "hotel", "nights", "pax", "currency", "total_amount",
        "amount_paid", "refunded_total", "customer_id", "created_by", "ticket_no",
        "supplier_status")}
    cust = world.customers[b["customer_id"]]
    if vulnerable("S15"):  # S15: internal cost/margin and full PII for every caller
        out["customer"] = cust
        out["supplier_cost"] = b["supplier_cost"]
        out["internal_margin"] = round(b["total_amount"] - b["supplier_cost"], 2)
    else:
        out["customer"] = {"name": cust["name"], "passport_no": mask_passport(cust["passport_no"])}
        if user.role == "admin":
            out["supplier_cost"] = b["supplier_cost"]
            out["internal_margin"] = round(b["total_amount"] - b["supplier_cost"], 2)
    return out


# ------------------------------------------------------------------------ meta / front end
@app.get("/_version")
async def version():
    return {"version": bugs.state.version}


@app.post("/_deploy")
async def deploy(body: DeployIn, request: Request):
    if request.headers.get("x-deploy-token") != DEPLOY_TOKEN:
        fail(403, "bad deploy token")
    try:
        bugs.deploy(body.version, body.mode, body.patched)
    except ValueError as exc:
        fail(422, str(exc))
    if body.reset:
        world.reset()
    return {"version": bugs.state.version, "deploys": bugs.state.deploys}


APP_JS = """// Waypoint Agent Portal __VERSION__
const API = "/api/v1";
const call = (m, p, b) => fetch(API + p, {method: m, headers: auth(), body: b && JSON.stringify(b)});
export const login = (email, password) => call("POST", "/auth/login", {email, password});
export const logout = () => call("POST", "/auth/logout");
export const me = () => call("GET", "/me");
export const search = (city) => call("GET", `/search?city=${city}`);
export const createHold = (offer_id, nights, pax) => call("POST", "/holds", {offer_id, nights, pax});
export const book = (hold_id, customer_id) => call("POST", "/bookings", {hold_id, customer_id});
export const listBookings = () => call("GET", "/bookings");
export const bookingDetail = (id) => call("GET", `/bookings/${id}`);
export const pay = (id, amount) => call("POST", `/bookings/${id}/pay`, {amount});
export const cancel = (id) => call("POST", `/bookings/${id}/cancel`);
export const refund = (id, amount) => call("POST", `/bookings/${id}/refunds`, {amount});
export const issueTicket = (id) => call("POST", `/bookings/${id}/ticket`);
export const invoice = (id) => call("GET", `/invoices/${id}`);
export const customer = (id) => call("GET", `/customers/${id}`);
export const listUsers = () => call("GET", "/users");
export const updateUser = (id, patch) => call("PATCH", `/users/${id}`, patch);
export const tenantUsers = (tid) => call("GET", `/admin/tenants/${tid}/users`);
export const testSupplier = (url) => call("POST", "/suppliers/test-connection", {url});
"""


@app.get("/static/app.js", response_class=PlainTextResponse)
async def app_js():
    return PlainTextResponse(APP_JS.replace("__VERSION__", bugs.state.version),
                             media_type="application/javascript")


@app.get("/", response_class=HTMLResponse)
async def index():
    return '<!doctype html><title>Waypoint Agent Portal</title><script type="module" src="/static/app.js"></script>'


# ----------------------------------------------------------------------------------- auth
@app.post("/api/v1/auth/login")
async def login(body: LoginIn):
    email = body.email.lower()
    user = next((u for u in world.users.values() if u.email == email), None)
    fails, since = world.failed_logins.get(email, (0, 0.0))
    if not vulnerable("S18") and fails >= LOCKOUT_AFTER and time.time() - since < 900:
        fail(429, "account temporarily locked")
    if user is None:
        fail(401, "unknown user" if vulnerable("S18") else "invalid credentials")  # S18 enumeration
    if body.password != PASSWORD:
        world.failed_logins[email] = (fails + 1, time.time())
        fail(401, "wrong password" if vulnerable("S18") else "invalid credentials")
    world.failed_logins.pop(email, None)
    token = "tok_" + uuid.uuid4().hex
    world.tokens[token] = (user.id, time.time() + TOKEN_TTL_S)
    return {"token": token, "expires_in": TOKEN_TTL_S,
            "user": {"id": user.id, "email": user.email, "name": user.name, "role": user.role,
                     "tenant_id": user.tenant_id}}


@app.post("/api/v1/auth/logout")
async def logout(request: Request, user: User = Depends(current_user)):
    if not vulnerable("S19"):  # S19: the token stays valid after logout
        world.tokens.pop(request.headers["authorization"][7:].strip(), None)
    return {"ok": True}


@app.get("/api/v1/me")
async def me(user: User = Depends(current_user)):
    return vars(user) | {"tenant": TENANTS[user.tenant_id]["name"]}


# ----------------------------------------------------------------------- search / hold / book
@app.get("/api/v1/search")
async def search(city: str, user: User = Depends(current_user)):
    markup = TENANTS[user.tenant_id]["markup_pct"]
    with world.db_lock:
        if vulnerable("S12"):  # S12: SQL injection through string concatenation
            rows = world.db.execute(
                f"SELECT id, city, name, rate, rating FROM hotels WHERE city = '{city}'"
            ).fetchall()
        else:
            rows = world.db.execute(
                "SELECT id, city, name, rate, rating FROM hotels WHERE city = ?", (city,)
            ).fetchall()
    return {"offers": [
        {"offer_id": r[0], "city": r[1], "hotel": r[2], "rate_per_night": r[3],
         "price_per_night": round(float(r[3]) * (1 + markup / 100), 2), "rating": r[4]}
        for r in rows]}


@app.post("/api/v1/holds")
async def create_hold(body: HoldIn, user: User = Depends(current_user)):
    if not vulnerable("S07") and not 1 <= body.pax <= 9:  # S07: negative/zero quantities
        fail(422, "pax must be between 1 and 9")
    with world.db_lock:
        row = world.db.execute("SELECT name, rate FROM hotels WHERE id = ?", (body.offer_id,)).fetchone()
    if not row:
        fail(404, "offer not found")
    markup = TENANTS[user.tenant_id]["markup_pct"]
    base = float(row[1]) * body.nights * body.pax
    hid = f"H-{world.next('hold'):05d}"
    world.holds[hid] = dict(id=hid, tenant_id=user.tenant_id, user=user.id, hotel=row[0],
                            nights=body.nights, pax=body.pax, base=base, markup_pct=markup,
                            used=False, expires=time.time() + 900)
    return {"hold_id": hid, "hotel": row[0], "total_amount": round(base * (1 + markup / 100), 2),
            "expires_in": 900}


@app.post("/api/v1/bookings")
async def create_booking(body: BookingIn, user: User = Depends(current_user)):
    need_role(user, "admin", "agent")
    hold = world.holds.get(body.hold_id)
    if not hold or hold["tenant_id"] != user.tenant_id or hold["used"] or hold["expires"] < time.time():
        fail(404, "hold not found or expired")
    if body.customer:
        cid = f"C{world.next('customer')}"
        world.customers[cid] = dict(id=cid, tenant_id=user.tenant_id, phone="",
                                    dob="", **body.customer.model_dump())
    else:
        cust = world.customers.get(body.customer_id or "")
        if not cust or cust["tenant_id"] != user.tenant_id:
            fail(404, "customer not found")
        cid = cust["id"]
    markup = hold["markup_pct"]
    if vulnerable("S06") and body.markup_pct is not None:  # S06: client sets the markup
        markup = body.markup_pct
    total = round(hold["base"] * (1 + markup / 100), 2)
    if vulnerable("S05") and body.total_amount is not None:  # S05: client sets the price
        total = body.total_amount
    hold["used"] = True
    bid = f"BK-{world.next('booking')}"
    world.bookings[bid] = dict(
        id=bid, tenant_id=user.tenant_id, customer_id=cid, created_by=user.id, hotel=hold["hotel"],
        nights=hold["nights"], pax=hold["pax"], currency="INR", status="pending_payment",
        total_amount=total, amount_paid=0.0, refunded_total=0.0, supplier_cost=hold["base"],
        ticket_no=None, supplier_status="unconfirmed")
    return public_booking(world.bookings[bid], user)


@app.get("/api/v1/bookings")
async def list_bookings(user: User = Depends(current_user)):
    return {"bookings": [
        public_booking(b, user) for b in world.bookings.values()
        if b["tenant_id"] == user.tenant_id and (user.role != "sub_agent" or b["created_by"] == user.id)]}


@app.get("/api/v1/bookings/{bid}")
async def get_booking(bid: str, user: User = Depends(current_user)):
    if vulnerable("S01"):  # S01: BOLA, no tenant check
        b = world.bookings.get(bid) or fail(404, "booking not found")
    else:
        b = tenant_booking(bid, user)
    return public_booking(b, user)


# ------------------------------------------------------------- pay / cancel / refund / ticket
@app.post("/api/v1/bookings/{bid}/pay")
async def pay(bid: str, body: PayIn, user: User = Depends(current_user)):
    need_role(user, "admin", "agent")
    b = tenant_booking(bid, user)
    if b["status"] != "pending_payment":
        fail(409, "booking is not awaiting payment")
    if abs(body.amount - b["total_amount"]) > 0.005:
        fail(400, "amount must equal the booking total")
    b["amount_paid"], b["status"] = body.amount, "paid"
    inv = dict(id="INV-" + bid[3:], booking_id=bid, tenant_id=b["tenant_id"], amount=body.amount,
               customer=world.customers[b["customer_id"]]["name"], issued="2026-11-19")
    world.invoices[inv["id"]] = inv
    return {"status": "paid", "invoice_id": inv["id"], "amount_paid": b["amount_paid"]}


@app.post("/api/v1/bookings/{bid}/cancel")
async def cancel(bid: str, user: User = Depends(current_user)):
    need_role(user, "admin", "agent")
    b = tenant_booking(bid, user)
    if b["status"] not in ("pending_payment", "paid"):
        fail(409, f"cannot cancel a {b['status']} booking")
    b["status"] = "cancelled"
    return {"status": "cancelled"}


@app.post("/api/v1/bookings/{bid}/refunds")
async def refund(bid: str, body: RefundIn, user: User = Depends(current_user)):
    need_role(user, "admin")
    b = tenant_booking(bid, user)
    if body.amount <= 0:
        fail(422, "refund must be positive")
    if b["amount_paid"] <= 0:
        fail(409, "nothing was paid")
    if not vulnerable("S11") and b["status"] != "cancelled":  # S11: refund without cancelling
        fail(409, "booking must be cancelled before refund")
    if not vulnerable("S08") and body.amount > b["amount_paid"]:  # S08: refund above amount paid
        fail(400, "refund exceeds amount paid")
    if (not vulnerable("S09") and b["refunded_total"] > 0  # S09: repeat refunds
            and b["refunded_total"] + body.amount > b["amount_paid"]):
        fail(400, "refunds would exceed amount paid")
    b["refunded_total"] = round(b["refunded_total"] + body.amount, 2)
    rid = f"RF-{world.next('refund'):04d}"
    world.refunds.append(dict(id=rid, booking_id=bid, amount=body.amount, by=user.id))
    return {"refund_id": rid, "refunded_total": b["refunded_total"]}


@app.post("/api/v1/bookings/{bid}/ticket")
async def issue_ticket(bid: str, user: User = Depends(current_user)):
    need_role(user, "admin", "agent")
    b = tenant_booking(bid, user)
    if not vulnerable("S10") and b["status"] != "paid":  # S10: ticket without payment
        fail(409, "booking must be paid before ticketing")
    b["ticket_no"] = f"TKT-{world.next('ticket'):05d}"
    if b["status"] == "paid":
        b["status"] = "ticketed"
    return {"ticket_no": b["ticket_no"]}


@app.get("/api/v1/invoices/{iid}")
async def get_invoice(iid: str, user: User = Depends(current_user)):
    num = int(iid.split("-")[1])  # malformed ids raise; the handler decides what leaks (S20)
    inv = world.invoices.get(f"INV-{num}")
    if not inv or (not vulnerable("S02") and inv["tenant_id"] != user.tenant_id):  # S02: BOLA
        fail(404, "invoice not found")
    return inv


@app.get("/api/v1/customers/{cid}")
async def get_customer(cid: str, user: User = Depends(current_user)):
    c = world.customers.get(cid)
    if not c or c["tenant_id"] != user.tenant_id:
        fail(404, "customer not found")
    if user.role == "sub_agent":
        return {**c, "passport_no": mask_passport(c["passport_no"]), "dob": None}
    return c


# ------------------------------------------------------------------------------- users
@app.get("/api/v1/users")
async def list_users(user: User = Depends(current_user)):
    need_role(user, "admin")
    return {"users": [vars(u) for u in world.users.values() if u.tenant_id == user.tenant_id]}


@app.patch("/api/v1/users/{uid}")
async def patch_user(uid: str, body: UserPatch, user: User = Depends(current_user)):
    target = world.users.get(uid)
    if not target or target.tenant_id != user.tenant_id:
        fail(404, "user not found")
    if user.role != "admin" and uid != user.id:
        fail(403, "you can only edit yourself")
    if body.role is not None:
        if body.role not in ROLES:
            fail(422, "unknown role")
        if user.role != "admin" and not vulnerable("S03"):  # S03: self-service role change
            fail(403, "only an admin can change roles")
        target.role = body.role
    target.name = body.name or target.name
    target.phone = body.phone or target.phone
    return vars(target)


@app.get("/api/v1/admin/tenants/{tid}/users")
async def tenant_users(tid: str, user: User = Depends(current_user)):
    if not vulnerable("S04"):  # S04: missing function-level authorization
        need_role(user, "admin")
        if tid != user.tenant_id:
            fail(403, "other tenant")
    return {"users": [vars(u) for u in world.users.values() if u.tenant_id == tid]}


# ---------------------------------------------------------- suppliers / webhook / hidden
@app.post("/api/v1/suppliers/test-connection")
async def test_connection(body: ConnIn, user: User = Depends(current_user)):
    need_role(user, "admin")
    host = (urlsplit(body.url).hostname or "").lower()
    if vulnerable("S13"):  # S13: SSRF. The "fetch" is simulated; nothing leaves the process.
        if host in ("169.254.169.254", "localhost", "127.0.0.1") or host.endswith(".internal"):
            return {"reachable": True, "body": "SYNTH-METADATA: iam-role=fake, key=FAKE-0000"}
        return {"reachable": True, "body": ""}
    if not host.endswith(".supplier.example"):
        fail(400, "only registered supplier hosts are allowed")
    return {"reachable": True, "body": ""}


@app.post("/webhooks/supplier")
async def supplier_webhook(request: Request):
    raw = await request.body()
    if not vulnerable("S14"):  # S14: unsigned supplier callbacks accepted
        want = hmac.new(SUPPLIER_SECRET, raw, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(want, request.headers.get("x-supplier-signature", "")):
            fail(401, "bad signature")
    try:
        data = json.loads(raw)
        b = world.bookings[data["booking_id"]]
    except (ValueError, KeyError):
        fail(400, "bad payload")
    b["supplier_status"] = data.get("supplier_status", "confirmed")
    if b["supplier_status"] == "confirmed" and b["status"] == "pending_payment":
        b["status"] = "paid"  # the forged callback marks an unpaid booking as paid
    return {"ok": True}


@app.get("/api/v0/bookings/{bid}")
async def legacy_booking(bid: str):
    if not vulnerable("S16"):  # S16: zombie v0 API, no auth
        return JSONResponse({"error": "gone"}, status_code=410)
    b = world.bookings.get(bid) or fail(404, "not found")
    return {"id": b["id"], "status": b["status"], "total": b["total_amount"],
            "customer": world.customers[b["customer_id"]]["name"]}


@app.get("/internal/debug/config")
async def debug_config():
    if not vulnerable("S17"):  # S17: shadow debug endpoint leaks secrets
        fail(404, "not found")
    return {"db": "sqlite:///:memory:", "supplier_webhook_key": SUPPLIER_SECRET.decode(),
            "jwt_secret": "synthetic-jwt-secret", "deploy_token": DEPLOY_TOKEN}
