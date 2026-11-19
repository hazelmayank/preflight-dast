"""Normal flows, rebuilt from recorded journeys (HAR).

A check needs a booking in a given state (booked, paid, cancelled ...). Instead of hard-coding the
app's steps, ``Flow`` takes the recorded normal journey, works out which earlier steps the target
step depends on (it uses ids they created, or acts on the same created resource), replays just
those through the gateway with fresh live ids, and hands back the request the check should send.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from preflight.recon.har_parser import Step, created_ids

from .client import ApiClient, Exchange, Inconclusive


def _strings(obj: Any) -> Iterable[str]:
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _strings(v)


@dataclass
class Run:
    live: dict[int, Exchange] = field(default_factory=dict)  # step index -> live exchange
    ids: dict[str, str] = field(default_factory=dict)  # recorded id -> live id
    tokens: dict[str, str] = field(default_factory=dict)  # session e-mail -> live token


@dataclass
class Request:
    session: str | None
    token: str | None
    method: str
    path: str
    body: Any
    template: str
    tenant_id: str | None


class Flow:
    def __init__(self, client: ApiClient, steps: list[Step]):
        self.client, self.steps = client, steps
        self.created = created_ids(steps)
        self._refs = [{x for x in _strings([s.body, s.path.split("/")]) if x in self.created}
                      for s in steps]
        self._resp = [set(_strings(s.resp)) & self.created if s.method != "GET" else set()
                      for s in steps]

    # -- finding steps -------------------------------------------------------------------------
    def find(self, method: str, template: str) -> int:
        for s in self.steps:
            if s.method == method.upper() and s.template == template and 200 <= s.status < 300:
                return s.idx
        raise Inconclusive(f"no recorded {method} {template} in the journeys")

    def _login_for(self, idx: int) -> int | None:
        who = self.steps[idx].session
        for j in range(idx - 1, -1, -1):
            s = self.steps[j]
            if s.session == who and s.path.endswith("/auth/login") and s.status == 200:
                return j
        return None

    def closure(self, target: int) -> list[int]:
        """Earlier steps ``target`` needs: its login, creators of ids it uses, and earlier
        state-changing steps on the same created resource."""
        inc, work = {target}, [target]
        while work:
            i = work.pop()
            new: set[int] = set()
            if self.steps[i].session and (j := self._login_for(i)) is not None:
                new.add(j)
            for ref in self._refs[i]:
                for j in range(i):
                    if ref in self._resp[j] or (self.steps[j].method != "GET" and ref in self._refs[j]):
                        new.add(j)
            for j in new - inc:
                inc.add(j)
                work.append(j)
        return sorted(inc)

    # -- running ---------------------------------------------------------------------------------
    def prepare(self, target: int, skip: Iterable[tuple[str, str]] = (), purpose: str = "") -> Run:
        """Replay the target's prerequisites live, except steps named in ``skip``."""
        run, skipped = Run(), set(skip)
        for i in self.closure(target):
            s = self.steps[i]
            if i == target or (s.method, s.template) in skipped:
                continue
            is_login = s.path.endswith("/auth/login")
            ex = self.client.call(
                s.method, self._sub(run, s.path), token=None if is_login else run.tokens.get(s.session),
                json=self._sub(run, s.body), label=f"setup: {s.method} {s.template}",
                actor=s.session or "", purpose=purpose)
            if not ex.ok:
                raise Inconclusive(f"setup step {s.method} {s.template} returned {ex.status}")
            run.live[i] = ex
            self._learn(run, s.resp, ex.json())
            if is_login:
                run.tokens[s.session or ""] = (ex.json() or {}).get("token", "")
        return run

    def request_for(self, run: Run, idx: int) -> Request:
        s = self.steps[idx]
        return Request(s.session, run.tokens.get(s.session or ""), s.method, self._sub(run, s.path),
                       self._sub(run, s.body), s.template, s.tenant_id)

    def quote_for(self, run: Run, idx: int, field_name: str) -> float | None:
        """The live price the server quoted: the earlier response field whose recorded value
        equals the recorded request amount."""
        body = self.steps[idx].body or {}
        recorded = body.get(field_name)
        for j, ex in run.live.items():
            for key, value in (self.steps[j].resp or {}).items():
                if value == recorded and isinstance(value, (int, float)):
                    live = (ex.json() or {}).get(key)
                    if isinstance(live, (int, float)):
                        return float(live)
        return None

    # -- id correlation --------------------------------------------------------------------------
    def _learn(self, run: Run, recorded: Any, live: Any) -> None:
        if isinstance(recorded, str) and isinstance(live, str):
            if recorded in self.created and recorded != live:
                run.ids[recorded] = live
        elif isinstance(recorded, dict) and isinstance(live, dict):
            for k, v in recorded.items():
                if k in live:
                    self._learn(run, v, live[k])
        elif isinstance(recorded, list) and isinstance(live, list):
            for a, b in zip(recorded, live, strict=False):
                self._learn(run, a, b)

    def _sub(self, run: Run, obj: Any) -> Any:
        if isinstance(obj, str):
            return "/".join(run.ids.get(seg, seg) for seg in obj.split("/")) if "/" in obj \
                else run.ids.get(obj, obj)
        if isinstance(obj, dict):
            return {k: self._sub(run, v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self._sub(run, v) for v in obj]
        return obj
