"""Control-room UI: reads the run state from ``out/`` and lets a human decide.

The human-only actions live here (approve/deny reserved actions, confirm invariants, kill switch),
which is why ``ui/`` is allowed to call them. Serve with:
``PREFLIGHT_OUT=out uvicorn preflight.ui.server:app --port 8001``.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

from preflight.discovery.rulebook import Rulebook
from preflight.safety.approval import ApprovalQueue
from preflight.safety.killswitch import KillSwitch

STATIC = Path(__file__).parent / "static"
app = FastAPI(title="Preflight control room", docs_url=None, redoc_url=None, openapi_url=None)


def out_dir() -> Path:
    return Path(os.environ.get("PREFLIGHT_OUT", "out"))


def _json(name: str, default: Any) -> Any:
    try:
        return json.loads((out_dir() / name).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def _audit_tail(n: int = 25) -> list[dict[str, Any]]:
    p = out_dir() / "audit.jsonl"
    if not p.exists():
        return []
    lines = p.read_text(encoding="utf-8").splitlines()[-n:]
    rows = []
    for line in lines:
        e = json.loads(line)
        d = e["data"]
        keys = ("method", "url", "status", "reason", "rule", "purpose")
        rows.append({"seq": e["seq"], "ts": e["ts"], "event": e["event"],
                     "summary": " ".join(str(d[k]) for k in keys if d.get(k))})
    return rows


class Who(BaseModel):
    by: str
    reason: str = ""


@app.get("/api/state")
def state() -> dict[str, Any]:
    queue = ApprovalQueue(out_dir() / "approvals.json")
    book = Rulebook(out_dir() / "rulebook.json")
    return {
        "run": _json("state.json", {}), "score": _json("score.json", {}),
        "pending_approvals": queue.pending(), "awaiting_confirmation": book.awaiting_confirmation(),
        "low_confidence": book.low_confidence_queue(), "audit_tail": _audit_tail(),
        "tickets": _json("tickets.json", []),
    }


def _human(who: Who) -> str:
    if not who.by.strip():
        raise HTTPException(422, "enter your name")
    return who.by.strip()


@app.post("/api/approvals/{approval_id}/approve")
def approve(approval_id: str, who: Who) -> dict[str, Any]:
    try:
        return ApprovalQueue(out_dir() / "approvals.json").approve(approval_id, _human(who))
    except (PermissionError, KeyError) as exc:
        raise HTTPException(400, str(exc)) from exc


@app.post("/api/approvals/{approval_id}/deny")
def deny(approval_id: str, who: Who) -> dict[str, Any]:
    try:
        return ApprovalQueue(out_dir() / "approvals.json").deny(approval_id, _human(who), who.reason)
    except (PermissionError, KeyError) as exc:
        raise HTTPException(400, str(exc)) from exc


@app.post("/api/invariants/confirm")
def confirm(who: Who) -> dict[str, Any]:
    try:
        return {"confirmed": Rulebook(out_dir() / "rulebook.json").confirm_invariants(_human(who))}
    except PermissionError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.post("/api/invariants/{inv_id}/confirm")
def confirm_one(inv_id: str, who: Who) -> dict[str, str]:
    try:
        Rulebook(out_dir() / "rulebook.json").confirm_low_confidence(inv_id, _human(who))
    except (PermissionError, KeyError) as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"confirmed": inv_id}


@app.post("/api/kill")
def kill(who: Who) -> dict[str, bool]:
    KillSwitch(out_dir() / "KILL").engage(f"operator {_human(who)} pressed the kill switch", by=who.by)
    return {"engaged": True}


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC / "index.html")
