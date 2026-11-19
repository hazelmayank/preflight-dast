"""Typed schemas for what the LLM may emit: invariant candidates and check plans.

The catalogue below mirrors ``specs/invariants.md`` (team-authored). The LLM may only say which of
those invariants applies to which endpoint; it cannot add new invariants. Anything that does not
validate is rejected and never executed.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

InvariantKind = Literal[
    "refund_bound", "tenant_isolation_read", "role_boundary", "price_integrity",
    "no_double_refund", "valid_transitions", "ownership_modify", "no_sensitive_exposure",
]

# id -> (kind, one-line statement); keep in step with specs/invariants.md
CATALOGUE: dict[str, tuple[str, str]] = {
    "INV-01": ("refund_bound", "a refund is never greater than the amount paid"),
    "INV-02": ("tenant_isolation_read", "a session reads only its own tenant's bookings"),
    "INV-03": ("role_boundary", "only an admin role may call admin-only actions"),
    "INV-04": ("price_integrity", "the amount charged equals the server-quoted price"),
    "INV-05": ("no_double_refund", "a paid booking is refunded at most once for its total"),
    "INV-06": ("valid_transitions", "an action is allowed only from a valid prior state"),
    "INV-07": ("ownership_modify", "only the owning agency may cancel or modify a booking"),
    "INV-08": ("no_sensitive_exposure", "responses never expose sensitive fields or secrets"),
}

# kind -> parameter names a proposal or plan may set (anything else is rejected)
ALLOWED_PARAMS: dict[str, set[str]] = {
    "refund_bound": set(),
    "tenant_isolation_read": set(),
    "role_boundary": {"allowed_roles", "tenant_param"},
    "price_integrity": set(),
    "no_double_refund": set(),
    "valid_transitions": {"related_endpoints"},
    "ownership_modify": set(),
    "no_sensitive_exposure": {"related_endpoints"},
}

HTTP_METHOD = r"^(GET|POST|PUT|PATCH|DELETE)$"
ParamValue = str | list[str]


class InvariantCandidate(BaseModel):
    """A business invariant the LLM thinks applies to an endpoint of the inferred map."""

    id: str = Field(pattern=r"^INV-\d{2}$")
    kind: InvariantKind
    statement: str = Field(min_length=8, max_length=300)
    method: str = Field(pattern=HTTP_METHOD)
    endpoint: str = Field(pattern=r"^/[^\s]*$")
    params: dict[str, ParamValue] = {}
    confidence: float = Field(ge=0, le=1)
    evidence: list[str] = []


class CheckPlan(BaseModel):
    """One plan per confirmed invariant. No invariant, no plan."""

    invariant_id: str = Field(pattern=r"^INV-\d{2}$")
    check: InvariantKind
    method: str = Field(pattern=HTTP_METHOD)
    endpoint: str = Field(pattern=r"^/[^\s]*$")
    params: dict[str, ParamValue] = {}
    rationale: str = Field(default="", max_length=300)


def param_problems(kind: str, params: dict) -> list[str]:
    extra = set(params) - ALLOWED_PARAMS[kind]
    return [f"parameter(s) not allowed for {kind}: {sorted(extra)}"] if extra else []
