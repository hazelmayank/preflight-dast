"""The inferred API map: endpoints with parameters, response fields, examples and provenance.

Built with no spec from three sources: recorded traffic (HAR), the front-end JS bundle, and the
access logs. Paths are templated (``/bookings/BK-1001`` -> ``/bookings/{booking_id}``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

_ID_SEGMENT = re.compile(r"^(?:[A-Za-z]{1,5}-\d+|[A-Za-z]{1,3}\d+|\d+|[0-9a-f]{12,}|tok_[0-9a-f]+)$")
_PARAM = re.compile(r"\{[^}]+\}")


def singular(word: str) -> str:
    word = word.lower()
    for suffix, rep in (("ies", "y"), ("ses", "s"), ("s", "")):
        if word.endswith(suffix) and len(word) > len(suffix) + 1:
            return word[: -len(suffix)] + rep
    return word


def templatize(path: str) -> str:
    """Replace id-like segments with ``{<previous segment singular>_id}``."""
    path = path.split("?")[0]
    out: list[str] = []
    for seg in path.split("/"):
        if seg and _ID_SEGMENT.match(seg) and out:
            prev = out[-1]
            out.append("{" + (singular(prev) if "{" not in prev else "id") + "_id}")
        else:
            out.append(seg)
    return "/".join(out)


def normalize_js_template(path: str) -> str:
    """JS template literal ``/bookings/${id}/pay`` -> ``/bookings/{booking_id}/pay``."""
    path = path.split("?")[0]
    out: list[str] = []
    for seg in path.split("/"):
        out.append("{" + (singular(out[-1]) if out and "{" not in out[-1] else "id") + "_id}"
                   if "${" in seg else seg)
    return "/".join(out)


def path_params(template: str) -> list[str]:
    return [m[1:-1] for m in _PARAM.findall(template)]


@dataclass
class Endpoint:
    method: str
    path: str
    sources: set[str] = field(default_factory=set)  # har | js | logs
    query_params: dict[str, set[str]] = field(default_factory=dict)  # name -> example values
    body_fields: dict[str, Any] = field(default_factory=dict)  # name -> example value
    response_fields: dict[str, set[str]] = field(default_factory=dict)  # role -> field names
    statuses: set[int] = field(default_factory=set)
    examples: dict[str, set[str]] = field(default_factory=dict)  # path param -> example ids
    auth_seen: bool = False
    roles_seen: set[str] = field(default_factory=set)

    @property
    def key(self) -> str:
        return f"{self.method} {self.path}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method, "path": self.path, "sources": sorted(self.sources),
            "query_params": {k: sorted(v)[:3] for k, v in self.query_params.items()},
            "body_fields": self.body_fields,
            "response_fields": {r: sorted(f) for r, f in self.response_fields.items()},
            "statuses": sorted(self.statuses),
            "examples": {k: sorted(v)[:6] for k, v in self.examples.items()},
            "auth_seen": self.auth_seen, "roles_seen": sorted(self.roles_seen),
        }


class ApiMap:
    def __init__(self) -> None:
        self.endpoints: dict[str, Endpoint] = {}
        self.journeys: list[dict[str, Any]] = []

    def endpoint(self, method: str, path: str) -> Endpoint:
        key = f"{method.upper()} {path}"
        if key not in self.endpoints:
            self.endpoints[key] = Endpoint(method.upper(), path)
        return self.endpoints[key]

    def get(self, method: str, path: str) -> Endpoint | None:
        return self.endpoints.get(f"{method.upper()} {path}")

    def to_dict(self) -> dict[str, Any]:
        return {"endpoints": [e.to_dict() for _, e in sorted(self.endpoints.items())],
                "journeys": self.journeys}

    def keys(self) -> set[str]:
        return set(self.endpoints)
