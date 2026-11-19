"""One check plan per confirmed invariant. The LLM proposes; this module validates.

A plan is accepted only if it references a confirmed invariant, uses that invariant's kind, method
and endpoint, sets only allowed params, and is the only plan for that invariant. No invariant, no plan.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError

from preflight.discovery.invariant_schema import CheckPlan, InvariantCandidate, param_problems
from preflight.discovery.prompts import PLAN_PROMPT_VERSION, PLAN_SYSTEM
from preflight.llm import LLMClient, LLMError


@dataclass
class PlanResult:
    plans: list[CheckPlan] = field(default_factory=list)
    rejected: list[dict[str, Any]] = field(default_factory=list)
    unplanned: list[str] = field(default_factory=list)  # confirmed invariants with no valid plan
    prompt_version: str = PLAN_PROMPT_VERSION
    llm: str = ""


def plan_checks(llm: LLMClient, confirmed: list[InvariantCandidate]) -> PlanResult:
    out = PlanResult(llm=llm.name)
    by_id = {c.id: c for c in confirmed}
    reply = llm.complete_json("plan_checks", PLAN_SYSTEM,
                              {"invariants": [c.model_dump() for c in confirmed]})
    items = reply.get("plans") if isinstance(reply, dict) else None
    if not isinstance(items, list):
        raise LLMError("reply has no 'plans' list")
    planned: set[str] = set()
    for raw in items:
        try:
            plan = CheckPlan.model_validate(raw)
            inv = by_id.get(plan.invariant_id)
            if inv is None:
                raise ValueError(f"{plan.invariant_id} is not a confirmed invariant")
            if plan.invariant_id in planned:
                raise ValueError(f"second plan for {plan.invariant_id}")
            if (plan.check, plan.method, plan.endpoint) != (inv.kind, inv.method, inv.endpoint):
                raise ValueError("plan must use the invariant's kind, method and endpoint")
            if problems := param_problems(plan.check, plan.params):
                raise ValueError(problems[0])
        except (ValidationError, ValueError) as exc:
            out.rejected.append({"item": raw, "reason": str(exc)})
            continue
        planned.add(plan.invariant_id)
        out.plans.append(plan)
    out.unplanned = sorted(set(by_id) - planned)
    return out
