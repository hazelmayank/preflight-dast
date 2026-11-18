"""Human approval queue for reserved (state-changing / risky) actions.

The gateway holds a reserved request and files a pending approval bound to the exact request
fingerprint (method, URL, params, body hash). Only a human can approve it, via the CLI
(``python -m preflight.safety.approval approve ID --by NAME``) or the operator UI. An approval is
single-use, expires, and is useless for any other request.

"An agent may never auto-approve" is enforced statically: ``tests/test_no_auto_approve.py``
fails the build if ``approve`` or ``human_release`` is called from agent code.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

_AGENT_LIKE = re.compile(r"^(agent|bot|preflight|system|auto|llm|orchestrator)", re.IGNORECASE)
STATE_CHANGING = frozenset({"POST", "PUT", "PATCH", "DELETE"})


@dataclass(frozen=True)
class ReservedRule:
    name: str
    methods: frozenset[str]
    path_re: re.Pattern[str]


class ReservedActions:
    """Reserved-action policy loaded from YAML."""

    def __init__(self, rules: list[ReservedRule], ttl_s: int, hold_all_state_changing: bool):
        self.rules, self.ttl_s = rules, ttl_s
        self.hold_all_state_changing = hold_all_state_changing

    @classmethod
    def from_file(cls, path: Path | str) -> ReservedActions:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        rules = [
            ReservedRule(
                r["name"],
                frozenset(m.upper() for m in r.get("methods", STATE_CHANGING)),
                re.compile(r["path_regex"]),
            )
            for r in raw.get("reserved", [])
        ]
        return cls(
            rules,
            int(raw.get("approval_ttl_seconds", 900)),
            bool(raw.get("state_changing_requires_approval", False)),
        )

    def match(self, method: str, path: str) -> str | None:
        """Return the reserved-action name that applies, or None."""
        method = method.upper()
        for rule in self.rules:
            if method in rule.methods and rule.path_re.search(path):
                return rule.name
        if self.hold_all_state_changing and method in STATE_CHANGING:
            return "state_changing"
        return None


class ApprovalQueue:
    """File-backed queue so a human in another process can decide."""

    def __init__(self, path: Path | str, ttl_s: int = 900, wall_clock=time.time):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.ttl_s, self._clock = ttl_s, wall_clock

    @staticmethod
    def fingerprint(method: str, url: str, params: Any, body: bytes) -> str:
        parts = [method.upper(), url, json.dumps(params or {}, sort_keys=True, default=str),
                 hashlib.sha256(body).hexdigest()]
        return hashlib.sha256("\n".join(parts).encode()).hexdigest()

    # -- agent-side (read / request / consume) ---------------------------------------------
    def request(self, rule: str, method: str, url: str, fp: str, actor: str, purpose: str) -> dict:
        """File a pending approval, or return the live one for the same fingerprint."""
        with self._locked():
            items = self._load()
            for rec in items.values():
                if rec["fingerprint"] == fp and self._live(rec):
                    return dict(rec)
            rec = {
                "id": "apr-" + uuid.uuid4().hex[:8], "status": "pending", "rule": rule,
                "method": method.upper(), "url": url, "fingerprint": fp, "actor": actor,
                "purpose": purpose, "created": self._clock(), "decided_by": None,
                "decided": None, "reason": "", "consumed": False,
            }
            items[rec["id"]] = rec
            self._save(items)
            return dict(rec)

    def get(self, approval_id: str) -> dict | None:
        rec = self._load().get(approval_id)
        return dict(rec) if rec else None

    def pending(self) -> list[dict]:
        return [r for r in self._load().values() if r["status"] == "pending" and self._live(r)]

    def is_approved(self, approval_id: str, fp: str) -> bool:
        rec = self._load().get(approval_id)
        return bool(
            rec and rec["status"] == "approved" and not rec["consumed"]
            and rec["fingerprint"] == fp and self._live(rec)
        )

    def consume(self, approval_id: str) -> None:
        with self._locked():
            items = self._load()
            items[approval_id]["consumed"] = True
            self._save(items)

    # -- human-side (approve / deny): never called from agent code -------------------------
    def approve(self, approval_id: str, approver: str) -> dict:
        return self._decide(approval_id, approver, "approved", "")

    def deny(self, approval_id: str, approver: str, reason: str = "") -> dict:
        return self._decide(approval_id, approver, "denied", reason)

    def _decide(self, approval_id: str, approver: str, status: str, reason: str) -> dict:
        if not approver.strip() or _AGENT_LIKE.match(approver.strip()):
            raise PermissionError("approvals must come from a named human")
        with self._locked():
            items = self._load()
            rec = items.get(approval_id)
            if rec is None or rec["status"] != "pending" or not self._live(rec):
                raise KeyError(f"no live pending approval {approval_id}")
            rec.update(status=status, decided_by=approver, decided=self._clock(), reason=reason)
            self._save(items)
            return dict(rec)

    # -- storage ------------------------------------------------------------------------------
    def _live(self, rec: dict) -> bool:
        return self._clock() - rec["created"] <= self.ttl_s

    def _load(self) -> dict[str, dict]:
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def _save(self, items: dict) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(items, indent=1), encoding="utf-8")
        os.replace(tmp, self.path)

    @contextlib.contextmanager
    def _locked(self):
        lock = self.path.with_suffix(".lock")
        deadline = time.monotonic() + 3
        while True:
            try:
                fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.close(fd)
                break
            except FileExistsError:
                with contextlib.suppress(OSError):
                    if time.time() - lock.stat().st_mtime > 10:  # stale lock
                        lock.unlink()
                if time.monotonic() > deadline:
                    raise TimeoutError("approval queue is locked") from None
                time.sleep(0.02)
        try:
            yield
        finally:
            lock.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    """CLI for the human operator: list | approve ID --by NAME | deny ID --by NAME [--out DIR]."""
    args = list(sys.argv[1:] if argv is None else argv)
    out = Path(args[args.index("--out") + 1]) if "--out" in args else Path("out")
    by = args[args.index("--by") + 1] if "--by" in args else ""
    queue = ApprovalQueue(out / "approvals.json")
    cmd = args[0] if args else "list"
    if cmd == "list":
        for r in queue.pending():
            print(f"{r['id']}  {r['rule']:<18} {r['method']} {r['url']}  ({r['purpose']})")
    elif cmd in ("approve", "deny") and len(args) > 1:
        rec = (queue.approve if cmd == "approve" else queue.deny)(args[1], by)
        print(f"{rec['id']}: {rec['status']} by {rec['decided_by']}")
    else:
        print(main.__doc__)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
