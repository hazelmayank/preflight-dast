"""The verifier: the only place a finding is declared.

A finding needs (1) the variation to violate the invariant in a first trial, (2) the normal flow in
that trial to have behaved correctly (the negative control), and (3) a second, independent trial to
violate it again. Anything else is "clean" or "inconclusive"; nothing unproven is reported.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from preflight.discovery.invariant_schema import CheckPlan

from .checks import REGISTRY
from .client import Inconclusive
from .oracle import CheckContext, CheckResult

REPRODUCTIONS = 2


@dataclass
class Finding:
    invariant_id: str
    kind: str
    method: str
    endpoint: str
    proof: list[dict[str, Any]]
    control: list[dict[str, Any]]
    reproduced: int
    impact: dict[str, Any]
    curl: str
    detected_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


@dataclass
class Verdict:
    invariant_id: str
    status: str  # finding | clean | inconclusive
    reason: str
    finding: Finding | None = None
    trials: int = 0


def curl_repro(ex_evidence: dict[str, Any]) -> str:
    """A curl command for the variation request (token placeholder; secrets are never stored)."""
    parts = [f"curl -s -X {ex_evidence['method']} '{ex_evidence['url']}'"]
    if ex_evidence["actor"] and "without credentials" not in ex_evidence["label"]:
        parts.append("-H 'Authorization: Bearer $TOKEN'")
    if ex_evidence["request_body"] is not None:
        import json
        parts += ["-H 'Content-Type: application/json'",
                  f"-d '{json.dumps(ex_evidence['request_body'])}'"]
    return " ".join(parts)


def verify(ctx: CheckContext, plan: CheckPlan) -> Verdict:
    check = REGISTRY[plan.check]
    try:
        first = check(ctx, plan, True)
        if first.control_ok is False:
            return Verdict(plan.invariant_id, "inconclusive",
                           "the normal flow did not behave correctly, so the control failed", trials=1)
        if not first.violated:
            return Verdict(plan.invariant_id, "clean", "the invariant held", trials=1)
        again: CheckResult = check(ctx, plan, False)
    except Inconclusive as exc:
        return Verdict(plan.invariant_id, "inconclusive", str(exc))
    if not again.violated:
        return Verdict(plan.invariant_id, "inconclusive",
                       "violated once but did not reproduce on the second trial", trials=2)
    variation = first.proof[-1].evidence()
    finding = Finding(
        plan.invariant_id, plan.check, plan.method, plan.endpoint,
        proof=[e.evidence() for e in first.proof[-1:]] + [e.evidence() for e in again.proof[-1:]],
        control=[e.evidence() for e in first.control], reproduced=REPRODUCTIONS,
        impact=first.impact, curl=curl_repro(variation))
    return Verdict(plan.invariant_id, "finding", "violated twice; control passed", finding, 2)
