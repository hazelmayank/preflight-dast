"""The oracle interface shared by all 8 property checks.

An oracle runs one normal flow plus one controlled variation through the gateway and reports
whether the invariant held. Oracles never declare findings; the verifier does that after 2x
reproduction and a passing control.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Protocol

from preflight.discovery.invariant_schema import CheckPlan

from .client import ApiClient, Exchange, Inconclusive
from .flow import Flow, Request


@dataclass
class Account:
    name: str
    tenant: str  # label, e.g. "acme"
    role: str
    email: str
    password: str


@dataclass
class Login:
    token: str
    user_id: str
    tenant_id: str
    role: str


@dataclass
class CheckResult:
    invariant_id: str
    violated: bool  # the variation produced the unsafe behaviour
    control_ok: bool | None  # normal flow behaved correctly (None: not evaluated this trial)
    proof: list[Exchange] = field(default_factory=list)  # minimal reproduction
    note: str = ""
    impact: dict[str, Any] = field(default_factory=dict)
    control: list[Exchange] = field(default_factory=list)  # evidence the normal flow behaved

    @property
    def passed(self) -> bool:
        return not self.violated


@dataclass
class CheckContext:
    client: ApiClient
    flow: Flow
    accounts: list[Account]
    amap: dict[str, Any]
    login_path: str = "/api/v1/auth/login"
    _logins: dict[str, Login] = field(default_factory=dict)

    def login(self, acct: Account) -> Login:
        if acct.name not in self._logins:
            ex = self.client.call("POST", self.login_path,
                                  json={"email": acct.email, "password": acct.password},
                                  label=f"login {acct.name}", actor=acct.name)
            data = ex.json() or {}
            if not ex.ok or "token" not in data:
                raise Inconclusive(f"cannot log in as {acct.name}: HTTP {ex.status}")
            u = data["user"]
            self._logins[acct.name] = Login(data["token"], u["id"], u["tenant_id"], u["role"])
        return self._logins[acct.name]

    def account(self, role: str, *, tenant: str | None = None, not_tenant_id: str | None = None,
                tenant_id: str | None = None) -> Account:
        for a in self.accounts:
            if a.role != role or (tenant and a.tenant != tenant):
                continue
            tid = self.login(a).tenant_id
            if (not_tenant_id and tid == not_tenant_id) or (tenant_id and tid != tenant_id):
                continue
            return a
        raise Inconclusive(f"no test account with role {role} matching the request")

    def tenants(self) -> list[str]:
        seen: list[str] = []
        for a in self.accounts:
            if a.tenant not in seen:
                seen.append(a.tenant)
        return seen

    def examples(self, template: str, limit: int = 8) -> list[str]:
        out: list[str] = []
        for e in self.amap["endpoints"]:
            if e["path"] == template:
                for vals in e["examples"].values():
                    out += [v for v in vals if v not in out]
        return out[:limit]

    def send(self, req: Request, label: str, token: str | None = None, actor: str = ""):
        return self.client.call(req.method, req.path, token=token or req.token, json=req.body,
                                label=label, actor=actor or req.session or "")


def fill(template: str, **params: str) -> str:
    return re.sub(r"\{([^}]+)\}", lambda m: params.get(m.group(1), m.group(0)), template)


def first_param(template: str) -> str:
    m = re.search(r"\{([^}]+)\}", template)
    if not m:
        raise Inconclusive(f"{template} has no path parameter")
    return m.group(1)


class Oracle(Protocol):
    kind: str

    def run(self, ctx: CheckContext, plan: CheckPlan, with_control: bool) -> CheckResult: ...
