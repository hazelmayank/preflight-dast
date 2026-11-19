"""Parse recorded traffic (HAR) into API-map entries and replayable journey steps."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .api_map import ApiMap, templatize

_ROOT_URL = re.compile(r"^[a-z]+://[^/]+")
_CREATED_ID = re.compile(r"^(?:[A-Za-z]{1,5}-\d+|[A-Za-z]{1,3}\d+|[0-9a-f]{12,})$")


@dataclass
class Step:
    idx: int
    method: str
    path: str  # actual path as recorded, no query
    template: str
    query: dict[str, str]
    body: Any
    status: int
    resp: Any
    session: str | None  # login e-mail that owns this step
    role: str | None
    tenant_id: str | None
    has_auth: bool

    @property
    def key(self) -> str:
        return f"{self.method} {self.template}"


def _json(text: str | None) -> Any:
    try:
        return json.loads(text) if text else None
    except ValueError:
        return None


def load_steps(har_path: Path | str) -> list[Step]:
    """Read HAR entries in order and attribute each to the session that logged in before it."""
    har = json.loads(Path(har_path).read_text(encoding="utf-8"))
    steps: list[Step] = []
    session = role = tenant = None
    for i, entry in enumerate(har["log"]["entries"]):
        req, resp = entry["request"], entry["response"]
        path = _ROOT_URL.sub("", req["url"]).split("?")[0]
        body = _json((req.get("postData") or {}).get("text"))
        rjson = _json(resp.get("content", {}).get("text"))
        if path.endswith("/auth/login") and resp["status"] == 200 and isinstance(body, dict):
            session = body.get("email")
            user = (rjson or {}).get("user", {})
            role, tenant = user.get("role"), user.get("tenant_id")
        steps.append(Step(
            i, req["method"], path, templatize(path),
            {q["name"]: q["value"] for q in req.get("queryString", [])},
            body, resp["status"], rjson, session, role, tenant,
            any(h["name"].lower() == "authorization" for h in req.get("headers", [])),
        ))
    return steps


def top_level_fields(obj: Any, depth: int = 0) -> set[str]:
    """Field names of a response, looking into one wrapper list/dict (e.g. {"offers": [...]})."""
    found: set[str] = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            found.add(k)
            if depth < 2 and isinstance(v, (dict, list)):
                found |= top_level_fields(v, depth + 1)
    elif isinstance(obj, list) and obj:
        found |= top_level_fields(obj[0], depth + 1)
    return found


def created_ids(steps: list[Step]) -> set[str]:
    """Ids that first appear in a POST response: resources the journey created."""
    seen_in_requests: set[str] = set()
    created: set[str] = set()

    def strings(o: Any):
        if isinstance(o, str):
            yield o
        elif isinstance(o, dict):
            for v in o.values():
                yield from strings(v)
        elif isinstance(o, list):
            for v in o:
                yield from strings(v)

    for s in steps:
        seen_in_requests |= {x for x in strings([s.body, s.path.split("/")]) if _CREATED_ID.match(x)}
        if s.method == "POST":
            created |= {x for x in strings(s.resp) if _CREATED_ID.match(x) and x not in seen_in_requests}
    return created


def add_to_map(amap: ApiMap, steps: list[Step]) -> None:
    for s in steps:
        ep = amap.endpoint(s.method, s.template)
        ep.sources.add("har")
        ep.statuses.add(s.status)
        ep.auth_seen |= s.has_auth
        if s.role:
            ep.roles_seen.add(s.role)
            ep.response_fields.setdefault(s.role, set()).update(top_level_fields(s.resp))
        for k, v in s.query.items():
            ep.query_params.setdefault(k, set()).add(v)
        if isinstance(s.body, dict):
            for k, v in s.body.items():
                ep.body_fields.setdefault(k, v)
        for tseg, aseg in zip(s.template.split("/"), s.path.split("/"), strict=False):
            if tseg.startswith("{"):
                ep.examples.setdefault(tseg[1:-1], set()).add(aseg)
    # journeys: ordered "METHOD template" per session, for the rule-discovery prompt
    by_session: dict[str, list[str]] = {}
    for s in steps:
        by_session.setdefault(s.session or "anonymous", []).append(f"{s.method} {s.template}")
    amap.journeys = [{"session": k, "role": next((x.role for x in steps if x.session == k), None),
                      "steps": v} for k, v in by_session.items()]
