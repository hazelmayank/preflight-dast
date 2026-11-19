"""The 8 MVP property checks, one per invariant in specs/invariants.md.

Each check runs the normal flow (which must behave correctly: that is the control) and then ONE
controlled variation, and asserts the safe behaviour from the spec. A check returns a CheckResult;
only the verifier turns repeated violations into a finding. Everything goes through ApiClient, so
the safety gateway sees every request.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import yaml

from preflight.discovery.invariant_schema import CheckPlan

from .client import Exchange, Inconclusive
from .oracle import CheckContext, CheckResult, fill, first_param

SENSITIVE_CFG = Path(__file__).with_name("sensitive_fields.yaml")


def _amount_key(body: Any) -> str:
    for k, v in (body or {}).items():
        if "amount" in k and isinstance(v, (int, float)):
            return k
    raise Inconclusive("recorded request has no numeric amount field")


def _res(plan: CheckPlan, violated: bool, control_ok: bool | None, proof: list[Exchange],
         note: str = "", control: list[Exchange] | None = None, **impact: Any) -> CheckResult:
    return CheckResult(plan.invariant_id, violated, control_ok, proof, note, impact, control or [])


# -- INV-01 refund never exceeds amount paid ---------------------------------------------------
def inv01_refund_bound(ctx: CheckContext, plan: CheckPlan, with_control: bool) -> CheckResult:
    idx, proof, control_ok = ctx.flow.find("POST", plan.endpoint), [], None
    if with_control:  # normal flow: refund equal to the amount paid
        req = ctx.flow.request_for(ctx.flow.prepare(idx, purpose=plan.invariant_id), idx)
        ex = ctx.send(req, "normal: refund equals amount paid")
        control_ok, proof = ex.ok, [ex]
    req = ctx.flow.request_for(ctx.flow.prepare(idx, purpose=plan.invariant_id), idx)
    key = _amount_key(req.body)
    paid = float(req.body[key])
    req.body[key] = round(paid * 2, 2)  # variation: more than was paid
    ex = ctx.send(req, "variation: refund greater than amount paid")
    return _res(plan, ex.ok, control_ok, [ex], control=proof, money_delta_inr=paid, kind="money")


# -- INV-02 tenant isolation on read -----------------------------------------------------------
def inv02_tenant_isolation(ctx: CheckContext, plan: CheckPlan, with_control: bool) -> CheckResult:
    param = first_param(plan.endpoint)
    tenant_a, tenant_b = ctx.tenants()[:2]
    admin_a = ctx.account("admin", tenant=tenant_a)
    admin_b = ctx.account("admin", tenant=tenant_b)
    tid_a, tid_b = ctx.login(admin_a).tenant_id, ctx.login(admin_b).tenant_id
    own = foreign = None
    for cand in ctx.examples(plan.endpoint):
        path = fill(plan.endpoint, **{param: cand})
        for owner, tid in ((admin_a, tid_a), (admin_b, tid_b)):
            ex = ctx.client.call(plan.method, path, token=ctx.login(owner).token,
                                 label="locate resource", actor=owner.name)
            if ex.ok and (ex.json() or {}).get("tenant_id") == tid:
                if tid == tid_a and own is None:
                    own = cand
                if tid == tid_b and foreign is None:
                    foreign = cand
        if own and foreign:
            break
    if not (own and foreign):
        raise Inconclusive("could not find one resource per tenant to compare")
    attacker = ctx.account("agent", tenant=tenant_a)
    token = ctx.login(attacker).token
    proof, control_ok = [], None
    if with_control:
        ex = ctx.client.call(plan.method, fill(plan.endpoint, **{param: own}), token=token,
                             label="normal: tenant A reads its own resource", actor=attacker.name)
        control_ok, proof = ex.ok and (ex.json() or {}).get("tenant_id") == tid_a, [ex]
    ex = ctx.client.call(plan.method, fill(plan.endpoint, **{param: foreign}), token=token,
                         label="variation: tenant A reads a tenant B resource", actor=attacker.name)
    leaked = ex.ok and (ex.json() or {}).get("tenant_id") == tid_b
    return _res(plan, leaked, control_ok, [ex], control=proof, cross_tenant=True)


# -- INV-03 role authority boundary ------------------------------------------------------------
def inv03_role_boundary(ctx: CheckContext, plan: CheckPlan, with_control: bool) -> CheckResult:
    allowed = plan.params.get("allowed_roles") or ["admin"]
    tparam = plan.params.get("tenant_param")
    admin = ctx.account(allowed[0])
    low = next((a for a in ctx.accounts if a.role not in allowed and a.tenant == admin.tenant
                and a.role == "sub_agent"), None) or next(
        (a for a in ctx.accounts if a.role not in allowed and a.tenant == admin.tenant), None)
    if low is None:
        raise Inconclusive("no lower-privilege account in the admin's tenant")
    path = fill(plan.endpoint, **({str(tparam): ctx.login(admin).tenant_id} if tparam else {}))
    proof, control_ok = [], None
    if with_control:
        ex = ctx.client.call(plan.method, path, token=ctx.login(admin).token,
                             label="normal: admin performs the admin action", actor=admin.name)
        control_ok, proof = ex.ok, [ex]
    ex = ctx.client.call(plan.method, path, token=ctx.login(low).token,
                         label=f"variation: same request as {low.role}", actor=low.name)
    return _res(plan, ex.ok, control_ok, [ex], control=proof, privilege=True)


# -- INV-04 charged price equals server-quoted price -------------------------------------------
def inv04_price_integrity(ctx: CheckContext, plan: CheckPlan, with_control: bool) -> CheckResult:
    idx, proof, control_ok = ctx.flow.find("POST", plan.endpoint), [], None
    key = _amount_key(ctx.flow.steps[idx].body)

    def attempt(factor: float, label: str) -> tuple[Exchange, float]:
        run = ctx.flow.prepare(idx, purpose=plan.invariant_id)
        quote = ctx.flow.quote_for(run, idx, key)
        if quote is None:
            raise Inconclusive("could not find the server's quoted price")
        req = ctx.flow.request_for(run, idx)
        req.body[key] = round(quote * factor, 2)
        return ctx.send(req, label), quote

    if with_control:
        ex, quote = attempt(1.0, "normal: pay the quoted amount")
        control_ok = ex.ok and abs(float((ex.json() or {}).get("amount_paid", -1)) - quote) < 0.01
        proof = [ex]
    ex, quote = attempt(0.5, "variation: client-supplied amount below the quote")
    charged = float((ex.json() or {}).get("amount_paid", quote)) if ex.ok else quote
    return _res(plan, ex.ok and charged < quote - 0.01, control_ok, [ex], control=proof,
                money_delta_inr=quote - charged, kind="money")


# -- INV-05 no double refund -------------------------------------------------------------------
def inv05_no_double_refund(ctx: CheckContext, plan: CheckPlan, with_control: bool) -> CheckResult:
    idx = ctx.flow.find("POST", plan.endpoint)
    req = ctx.flow.request_for(ctx.flow.prepare(idx, purpose=plan.invariant_id), idx)
    first = ctx.send(req, "normal: first refund")
    if not first.ok:
        return _res(plan, False, False, [], "first refund failed", control=[first])
    second = ctx.send(req, "variation: the same refund again")
    paid = float(req.body[_amount_key(req.body)])
    return _res(plan, second.ok, True, [second], control=[first], money_delta_inr=paid, kind="money")


# -- INV-06 valid state transitions only -------------------------------------------------------
def inv06_valid_transitions(ctx: CheckContext, plan: CheckPlan, with_control: bool) -> CheckResult:
    related = plan.params.get("related_endpoints") or []
    if not related:
        raise Inconclusive("plan names no prerequisite steps to skip")
    idx = ctx.flow.find("POST", plan.endpoint)
    skip = {("POST", str(t)) for t in related}
    proof, control_ok = [], None
    if with_control:  # normal order: book -> pay -> cancel -> refund
        req = ctx.flow.request_for(ctx.flow.prepare(idx, purpose=plan.invariant_id), idx)
        ex = ctx.send(req, "normal: refund after pay and cancel")
        control_ok, proof = ex.ok, [ex]
    run = ctx.flow.prepare(idx, skip=skip, purpose=plan.invariant_id)
    ex = ctx.send(ctx.flow.request_for(run, idx), "variation: refund on a booking that was never paid")
    return _res(plan, ex.ok, control_ok, [ex], control=proof, kind="money")


# -- INV-07 ownership required to modify -------------------------------------------------------
def inv07_ownership_modify(ctx: CheckContext, plan: CheckPlan, with_control: bool) -> CheckResult:
    idx, proof, control_ok = ctx.flow.find("POST", plan.endpoint), [], None
    owner_tid = ctx.flow.steps[idx].tenant_id
    if with_control:
        req = ctx.flow.request_for(ctx.flow.prepare(idx, purpose=plan.invariant_id), idx)
        ex = ctx.send(req, "normal: the owning agency cancels its booking")
        control_ok, proof = ex.ok, [ex]
    req = ctx.flow.request_for(ctx.flow.prepare(idx, purpose=plan.invariant_id), idx)
    other = next((a for a in ctx.accounts if a.role == "agent"
                  and ctx.login(a).tenant_id != owner_tid), None)
    if other is None:
        raise Inconclusive("no agent from a different agency")
    ex = ctx.send(req, "variation: a different agency cancels that booking",
                  token=ctx.login(other).token, actor=other.name)
    return _res(plan, ex.ok, control_ok, [ex], control=proof, cross_tenant=True)


# -- INV-08 no sensitive-field exposure --------------------------------------------------------
def sensitive_keys(obj: Any, cfg: dict[str, list[str]], path: str = "") -> Iterator[str]:
    always = [re.compile(p, re.I) for p in cfg["always_sensitive"]]
    masked = [re.compile(p, re.I) for p in cfg["masked_when_present"]]
    if isinstance(obj, dict):
        for k, v in obj.items():
            here = f"{path}.{k}" if path else k
            if any(p.fullmatch(k) for p in always) and v not in (None, ""):
                yield here
            elif any(p.fullmatch(k) for p in masked) and isinstance(v, str) and "*" not in v:
                yield here
            yield from sensitive_keys(v, cfg, here)
    elif isinstance(obj, list):
        for item in obj[:20]:
            yield from sensitive_keys(item, cfg, path)


def inv08_no_sensitive_exposure(ctx: CheckContext, plan: CheckPlan, with_control: bool) -> CheckResult:
    cfg = yaml.safe_load(SENSITIVE_CFG.read_text(encoding="utf-8"))
    tenant = ctx.tenants()[0]
    owner, low = ctx.account("admin", tenant=tenant), ctx.account("agent", tenant=tenant)
    related = [str(r) for r in plan.params.get("related_endpoints", [])]

    def readable(template: str, who) -> tuple[Exchange | None, str]:
        """First example resource this account can read at ``template``."""
        param = first_param(template)
        for cand in ctx.examples(template):
            ex = ctx.client.call("GET", fill(template, **{param: cand}),
                                 token=ctx.login(who).token, label="locate resource", actor=who.name)
            if ex.ok:
                return ex, cand
        return None, ""

    proof, control_ok, hits, found = [], None, [], []
    if with_control:  # normal flow: the owner reads the invoice and gets only permitted fields
        ex, _ = readable(plan.endpoint, owner)
        control_ok = bool(ex) and not list(sensitive_keys(ex.json(), cfg))
        proof = [ex] if ex else []
    reads = [plan.endpoint] + [r for r in related if "{" in r]
    for template in reads:  # variation 1: the same kind of read as a lower-privilege role
        ex, cand = readable(template, low)
        if ex and (keys := list(sensitive_keys(ex.json(), cfg))):
            ex.label = f"variation: {low.role} reads {template}"
            hits.append(ex)
            found += keys
    for template in related:  # variation 2: internal/debug routes requested with no credentials
        if "{" not in template:
            ex = ctx.client.call("GET", template, label=f"variation: {template} without credentials")
            if ex.ok and (keys := list(sensitive_keys(ex.json(), cfg))):
                hits.append(ex)
                found += keys
    return _res(plan, bool(hits), control_ok, hits, control=proof, data_exposure=True,
                fields=sorted(set(found))[:12])


REGISTRY = {
    "refund_bound": inv01_refund_bound,
    "tenant_isolation_read": inv02_tenant_isolation,
    "role_boundary": inv03_role_boundary,
    "price_integrity": inv04_price_integrity,
    "no_double_refund": inv05_no_double_refund,
    "valid_transitions": inv06_valid_transitions,
    "ownership_modify": inv07_ownership_modify,
    "no_sensitive_exposure": inv08_no_sensitive_exposure,
}
