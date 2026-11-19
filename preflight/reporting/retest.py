"""Retest: re-run a ticket's stored reproduction after a fix deploy and update its status."""

from __future__ import annotations

from preflight.discovery.invariant_schema import CheckPlan
from preflight.execution.checks import REGISTRY
from preflight.execution.client import Inconclusive
from preflight.execution.oracle import CheckContext

from .tickets import TicketStore


def retest_ticket(ctx: CheckContext, store: TicketStore, ticket_id: str, version: str) -> str:
    """Return "resolved", "reopened" or "inconclusive" and record it in the ticket history."""
    plan = CheckPlan.model_validate(store.get(ticket_id)["plan"])
    try:
        res = REGISTRY[plan.check](ctx, plan, True)
    except Inconclusive as exc:
        store.add_history(ticket_id, "retest inconclusive", f"{version}: {exc}")
        return "inconclusive"
    if res.control_ok is False:
        store.add_history(ticket_id, "retest inconclusive",
                          f"{version}: the normal flow failed, so the control did not pass")
        return "inconclusive"
    if res.violated:
        store.add_history(ticket_id, "reopened", f"still violated on {version}", status="Reopened")
        return "reopened"
    store.add_history(ticket_id, "resolved",
                      f"invariant holds on {version}; normal flow still passes", status="Resolved")
    return "resolved"
