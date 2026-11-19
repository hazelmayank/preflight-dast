"""Versioned prompts. The version is logged with every LLM action (explainability)."""

from .invariant_schema import ALLOWED_PARAMS, CATALOGUE

INVARIANTS_PROMPT_VERSION = "invariants-v1"
PLAN_PROMPT_VERSION = "plan-v1"

INVARIANTS_SYSTEM = (
    "You help verify the business rules of our own synthetic B2B travel app before release. "
    "Given an inferred API map, say which invariant from the fixed catalogue applies to which "
    "endpoint of the map. Do not invent invariants or endpoints. Reply with JSON "
    '{"invariants": [{"id","kind","statement","method","endpoint","params","confidence","evidence"}]}. '
    f"Catalogue: {CATALOGUE}. Allowed params per kind: "
    f"{ {k: sorted(v) for k, v in ALLOWED_PARAMS.items()} }."
)

PLAN_SYSTEM = (
    "For each confirmed invariant, give exactly one check plan using the same kind, method and "
    "endpoint. Reply with JSON "
    '{"plans": [{"invariant_id","check","method","endpoint","params","rationale"}]}.'
)
