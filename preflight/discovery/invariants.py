"""Ask the LLM which catalogued invariants apply to which endpoints, then validate strictly.

A proposal is accepted only if it validates against the schema, uses the catalogued kind for its id,
sets only allowed params, and names an endpoint/method that exists in the inferred map. Everything
else is rejected with a reason and never executed. Confidence below the threshold goes to the human
confirmation queue.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError

from preflight.llm import LLMClient, LLMError

from .invariant_schema import CATALOGUE, InvariantCandidate, param_problems
from .prompts import INVARIANTS_PROMPT_VERSION, INVARIANTS_SYSTEM

DEFAULT_LOW_CONFIDENCE = 0.6


@dataclass
class Proposal:
    accepted: list[InvariantCandidate] = field(default_factory=list)
    rejected: list[dict[str, Any]] = field(default_factory=list)  # {"item": ..., "reason": ...}
    prompt_version: str = INVARIANTS_PROMPT_VERSION
    llm: str = ""
    low_confidence_ids: list[str] = field(default_factory=list)


def _map_index(amap: dict[str, Any]) -> set[tuple[str, str]]:
    return {(e["method"], e["path"]) for e in amap["endpoints"]}


def validate_candidate(raw: Any, known: set[tuple[str, str]]) -> InvariantCandidate:
    """Return a valid candidate or raise ValueError with a reason."""
    try:
        cand = InvariantCandidate.model_validate(raw)
    except ValidationError as exc:
        raise ValueError(f"schema: {exc.errors()[0]['msg']}") from exc
    cat = CATALOGUE.get(cand.id)
    if cat is None:
        raise ValueError(f"{cand.id} is not in the invariant catalogue")
    if cat[0] != cand.kind:
        raise ValueError(f"{cand.id} must have kind {cat[0]}, got {cand.kind}")
    if problems := param_problems(cand.kind, cand.params):
        raise ValueError(problems[0])
    if (cand.method, cand.endpoint) not in known:
        raise ValueError(f"{cand.method} {cand.endpoint} is not in the inferred API map")
    for extra in cand.params.get("related_endpoints", []):
        if not any(p == extra for _, p in known):
            raise ValueError(f"related endpoint {extra} is not in the inferred API map")
    return cand


def propose_invariants(llm: LLMClient, amap: dict[str, Any],
                       low_confidence_below: float = DEFAULT_LOW_CONFIDENCE) -> Proposal:
    out = Proposal(llm=llm.name)
    reply = llm.complete_json("propose_invariants", INVARIANTS_SYSTEM, {"api_map": amap})
    items = reply.get("invariants") if isinstance(reply, dict) else None
    if not isinstance(items, list):
        raise LLMError("reply has no 'invariants' list")
    known, seen = _map_index(amap), set()
    for raw in items:
        try:
            cand = validate_candidate(raw, known)
            if cand.id in seen:
                raise ValueError(f"duplicate proposal for {cand.id}")
        except ValueError as exc:
            out.rejected.append({"item": raw, "reason": str(exc)})
            continue
        seen.add(cand.id)
        out.accepted.append(cand)
        if cand.confidence < low_confidence_below:
            out.low_confidence_ids.append(cand.id)
    return out
