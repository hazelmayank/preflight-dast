"""ApiClient: how every check talks to the target. A thin wrapper over the safety gateway.

It records each exchange as evidence (secrets redacted) and, when the gateway holds a reserved
action for human approval, waits for a human to decide, then resends with the approval id.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from preflight.safety.audit import redact_json, redact_text
from preflight.safety.gateway import ApprovalRequired, Gateway, TransportError


class Inconclusive(Exception):
    """The check could not run to a verdict (setup failed, approval denied or timed out)."""


@dataclass
class Exchange:
    label: str
    actor: str
    method: str
    path: str
    url: str
    status: int
    request_body: Any
    approval_id: str | None = None
    raw: str = field(default="", repr=False)  # unredacted; never persisted

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def json(self) -> Any:
        try:
            return json.loads(self.raw)
        except ValueError:
            return None

    def evidence(self) -> dict[str, Any]:
        """Redacted, size-capped record safe to store in a ticket."""
        return {"label": self.label, "actor": self.actor, "method": self.method, "path": self.path,
                "url": self.url, "status": self.status,
                "request_body": redact_json(self.request_body), "approval_id": self.approval_id,
                "response": redact_text(self.raw, 600)}


class ApiClient:
    def __init__(self, gateway: Gateway, base_url: str, approval_wait_s: float = 300.0,
                 on_wait: Callable[[str, str], None] | None = None,
                 sleep: Callable[[float], None] = time.sleep):
        self.gw, self.base = gateway, base_url.rstrip("/")
        self.approval_wait_s, self.on_wait, self._sleep = approval_wait_s, on_wait, sleep

    def call(self, method: str, path: str, *, token: str | None = None, json: Any = None,
             params: dict[str, Any] | None = None, label: str = "", actor: str = "",
             purpose: str = "") -> Exchange:
        url = self.base + path
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        approval_id = None
        resp = None
        for _ in range(2):  # a second pass happens only after a human approved
            try:
                resp = self.gw.send(method, url, headers=headers, json_body=json, params=params,
                                    actor="agent", purpose=purpose or label, approval_id=approval_id)
                break
            except ApprovalRequired as held:
                approval_id = self._wait(held.approval_id, label)
            except TransportError as exc:
                raise Inconclusive(str(exc)) from exc
        if resp is None:
            raise Inconclusive(f"{label}: approval did not release the request")
        return Exchange(label, actor, method.upper(), path, url, resp.status, json,
                        approval_id, resp.text)

    def _wait(self, approval_id: str, label: str) -> str:
        if self.on_wait:
            self.on_wait(approval_id, label)
        deadline = time.monotonic() + self.approval_wait_s
        while time.monotonic() < deadline:
            self.gw.killswitch.check()
            rec = self.gw.approvals.get(approval_id)
            if rec and rec["status"] == "approved":
                return approval_id
            if rec and rec["status"] == "denied":
                raise Inconclusive(f"approval {approval_id} denied: {rec.get('reason', '')}")
            self._sleep(0.2)
        raise Inconclusive(f"approval {approval_id} not decided within {self.approval_wait_s:.0f}s")
