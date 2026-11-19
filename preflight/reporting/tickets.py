"""Tickets: one per finding, with owner, evidence, impact, fix, curl repro and retest history."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

import yaml

from preflight.discovery.invariant_schema import CheckPlan
from preflight.triage.triage import Triaged

FIXES = Path(__file__).with_name("fixes.yaml")
OPEN_STATES = ("Open", "Reopened")


def _now() -> float:
    return time.time()


class TicketStore:
    def __init__(self, out_dir: Path | str):
        self.out = Path(out_dir)
        self.path = self.out / "tickets.json"
        self.md_dir = self.out / "tickets"
        self.md_dir.mkdir(parents=True, exist_ok=True)

    def all(self) -> list[dict[str, Any]]:
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []

    def get(self, ticket_id: str) -> dict[str, Any]:
        for t in self.all():
            if t["id"] == ticket_id:
                return t
        raise KeyError(ticket_id)

    def open_tickets(self) -> list[dict[str, Any]]:
        return [t for t in self.all() if t["status"] in OPEN_STATES]

    def find_by_key(self, key: str) -> dict[str, Any] | None:
        return next((t for t in self.all() if t["dedupe_key"] == key), None)

    def file(self, tri: Triaged, plan: CheckPlan, version: str, seconds_to_proof: float) -> dict:
        """Create a ticket, or record a repeat sighting on the existing one (dedupe)."""
        if existing := self.find_by_key(tri.dedupe_key):
            self.add_history(existing["id"], "seen again", f"re-detected on {version}")
            return self.get(existing["id"])
        f = tri.finding
        fixes = yaml.safe_load(FIXES.read_text(encoding="utf-8"))
        ticket = {
            "id": f"FIND-{f.invariant_id}", "invariant_id": f.invariant_id, "kind": f.kind,
            "dedupe_key": tri.dedupe_key, "status": "Open", "severity": tri.severity,
            "severity_reasons": tri.severity_reasons, "owner": tri.owner,
            "title": f"{f.invariant_id}: {f.method} {f.endpoint} violates '{f.kind}'",
            "method": f.method, "endpoint": f.endpoint, "impact": tri.impact,
            "evidence": {"control": f.control, "proof": f.proof}, "reproduced": f.reproduced,
            "curl": f.curl, "suggested_fix": fixes[f.kind], "plan": plan.model_dump(),
            "opened_on_version": version, "opened_at": _now(),
            "seconds_deploy_to_proof": round(seconds_to_proof, 1),
            "history": [{"ts": _now(), "event": "opened",
                         "detail": f"reproduced {f.reproduced}x with a passing control on {version}"}],
        }
        self._write(self.all() + [ticket])
        self._render(ticket)
        return ticket

    def add_history(self, ticket_id: str, event: str, detail: str, status: str | None = None) -> None:
        tickets = self.all()
        for t in tickets:
            if t["id"] == ticket_id:
                t["history"].append({"ts": _now(), "event": event, "detail": detail})
                if status:
                    t["status"] = status
                self._render(t)
        self._write(tickets)

    def _write(self, tickets: list[dict[str, Any]]) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(tickets, indent=1), encoding="utf-8")
        os.replace(tmp, self.path)

    def _render(self, t: dict[str, Any]) -> None:
        def ex(e: dict) -> str:
            return (f"- **{e['label']}** as `{e['actor'] or 'anonymous'}`: `{e['method']} {e['path']}` "
                    f"-> HTTP {e['status']}\n  - request: `{json.dumps(e['request_body'])}`\n"
                    f"  - response: `{e['response'][:300]}`")

        lines = [
            f"# {t['title']}", "",
            f"**Status:** {t['status']} · **Severity:** {t['severity']} · "
            f"**Owner:** {t['owner']['team']} ({t['owner']['contact']})", "",
            "## Business impact", t["impact"], "",
            "## Why this severity", *[f"- {r}" for r in t["severity_reasons"]], "",
            "## Evidence", f"Reproduced {t['reproduced']}x; the normal flow (control) passed.", "",
            "**Normal flow (control)**", *[ex(e) for e in t["evidence"]["control"]], "",
            "**Violation**", *[ex(e) for e in t["evidence"]["proof"]], "",
            "## Reproduce", "```", t["curl"], "```",
            "_The request needs the prior booking state described by the normal flow; the token "
            "placeholder is never stored._", "",
            "## Suggested fix", t["suggested_fix"], "",
            "## History", *[f"- {time.strftime('%H:%M:%S', time.localtime(h['ts']))} · "
                            f"**{h['event']}**: {h['detail']}" for h in t["history"]],
        ]
        (self.md_dir / f"{t['id']}.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
