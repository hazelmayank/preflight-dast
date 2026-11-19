"""Typed schemas for what the LLM may emit: rule candidates and test plans.

Anything that does not validate is rejected and never executed. Each rule ``kind`` maps to exactly
one deterministic oracle in ``preflight/execution/oracles`` and to a closed set of parameters.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

RuleKind = Literal[
    "tenant_isolation", "role_restricted", "privilege_escalation", "amount_bound",
    "cumulative_bound", "price_integrity", "quantity_positive", "step_precedence",
    "auth_required", "webhook_signature", "sql_injection", "ssrf_guard", "logout_invalidates",
    "login_uniform", "error_hygiene", "no_internal_fields",
]

# kind -> parameter names the plan may set (anything else is rejected)
ORACLE_PARAMS: dict[str, set[str]] = {
    "tenant_isolation": {"id_param"},
    "role_restricted": {"allowed_roles", "tenant_param"},
    "privilege_escalation": {"field", "escalate_to"},
    "amount_bound": {"field", "factor"},
    "cumulative_bound": {"field"},
    "price_integrity": {"inject"},
    "quantity_positive": {"field", "bad_value"},
    "step_precedence": {"skip_method", "skip_endpoint"},
    "auth_required": set(),
    "webhook_signature": {"resource_endpoint", "payload"},
    "sql_injection": {"param"},
    "ssrf_guard": {"field"},
    "logout_invalidates": {"check_endpoint"},
    "login_uniform": set(),
    "error_hygiene": {"param"},
    "no_internal_fields": {"fields"},
}

Scalar = str | int | float | bool | None
ParamValue = Scalar | list[Scalar] | dict[str, Scalar]


class RuleCandidate(BaseModel):
    """A business rule the platform appears to enforce, proposed from observed traffic."""

    id: str = Field(pattern=r"^R-[a-z0-9_-]{3,60}$")
    kind: RuleKind
    statement: str = Field(min_length=8, max_length=300)  # e.g. refund.amount <= booking.amount_paid
    method: str = Field(pattern=r"^(GET|POST|PUT|PATCH|DELETE)$")
    endpoint: str = Field(pattern=r"^/[^\s]*$")
    params: dict[str, ParamValue] = {}
    confidence: float = Field(ge=0, le=1)
    evidence: list[str] = []


class TestPlan(BaseModel):
    """A targeted test for one confirmed rule. No rule, no plan."""

    __test__ = False  # not a pytest class

    rule_id: str
    oracle: RuleKind
    method: str = Field(pattern=r"^(GET|POST|PUT|PATCH|DELETE)$")
    endpoint: str = Field(pattern=r"^/[^\s]*$")
    params: dict[str, ParamValue] = {}
    rationale: str = Field(default="", max_length=300)


def validate_params(kind: str, params: dict[str, Any]) -> list[str]:
    """Return a list of problems; empty means the parameters are allowed for this kind."""
    extra = set(params) - ORACLE_PARAMS[kind]
    return [f"parameter(s) not allowed for {kind}: {sorted(extra)}"] if extra else []
