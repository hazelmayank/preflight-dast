"""The orchestrator: a deterministic state machine that drives one release-safety run.

IDLE -> DETECTING -> MAPPING -> PROPOSING -> AWAITING_CONFIRM -> PLANNING -> CHECKING
     -> REPORTING -> MONITORING -> (new deploy) DETECTING -> MAPPING -> RETESTING -> DONE
PAUSED_SAFETY is entered from anywhere when the kill switch is engaged or a policy file is
tampered with; the run stops until a human releases the switch and restarts it.
"""

from __future__ import annotations

import json
import time
from typing import Any

from preflight.discovery.invariant_schema import CheckPlan
from preflight.discovery.invariants import propose_invariants
from preflight.discovery.rulebook import Rulebook
from preflight.execution.client import ApiClient
from preflight.execution.flow import Flow
from preflight.execution.oracle import CheckContext
from preflight.execution.verifier import verify
from preflight.llm import LLMClient, load_llm_config
from preflight.planning.planner import plan_checks
from preflight.recon.har_parser import load_steps
from preflight.reporting.retest import retest_ticket
from preflight.reporting.tickets import TicketStore
from preflight.safety.audit import AuditLog
from preflight.safety.gateway import Gateway, ScopeViolation
from preflight.safety.killswitch import KillSwitchEngaged
from preflight.triage.triage import triage

from . import watcher
from .config import Config
from .pipeline import Recon, build_map
from .state import RunState


class Orchestrator:
    def __init__(self, cfg: Config, gateway: Gateway, llm: LLMClient):
        self.cfg, self.gw, self.llm = cfg, gateway, llm
        self.rs = RunState(cfg.out_dir / "state.json")
        self.client = ApiClient(gateway, cfg.base_url, cfg.approval_wait_s, on_wait=self._on_wait)
        self.rulebook = Rulebook(cfg.out_dir / "rulebook.json")
        self.tickets = TicketStore(cfg.out_dir)
        self.plans: dict[str, CheckPlan] = {}
        self.recon: Recon | None = None
        self.ctx: CheckContext | None = None
        self.snapshot: watcher.Snapshot | None = None
        self.t_detect = time.time()
        self.first_proof_s: float | None = None  # seconds from deploy detection to first proof
        self.false_positives: int | None = None
        self.checks: dict[str, Any] = {}
        self.state = "IDLE"

    # -- bookkeeping ----------------------------------------------------------------------------
    def _to(self, state: str, msg: str) -> None:
        self.state = state
        self.rs.event(state, msg)
        self._publish()

    def _on_wait(self, approval_id: str, label: str) -> None:
        self.rs.set(waiting_approval={"id": approval_id, "label": label})
        self.rs.event(self.state, f"waiting for a human to approve {approval_id}: {label}")

    def safety_summary(self) -> dict[str, Any]:
        """Counters for the safety panel, recomputed from the audit log (not trusted state)."""
        events = []
        path = self.gw.audit.path
        if path.exists():
            events = [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x]
        out_of_scope = 0
        for e in events:
            if e["event"] == "request" and e["data"].get("channel", "target") == "target":
                try:
                    self.gw.scope.check(e["data"]["method"], e["data"]["url"])
                except ScopeViolation:
                    out_of_scope += 1
        ver = AuditLog.verify(path)
        return {"requests_sent": self.gw.stats["sent"], "refused": self.gw.stats["refused"],
                "held_for_approval": self.gw.stats["held"],
                "approvals_used": sum(1 for e in events if e["event"] == "approval_used"),
                "out_of_scope_sent": out_of_scope, "audit_entries": ver.entries,
                "audit_chain_ok": ver.ok, "kill_switch": self.gw.killswitch.is_engaged()}

    def _publish(self) -> None:
        tickets = self.tickets.all()
        first = self.first_proof_s
        self.rs.set(
            version=self.snapshot.version if self.snapshot else None,
            inventory=[vars(x) for x in self.recon.labels] if self.recon else [],
            checks=self.checks, safety=self.safety_summary(),
            tickets=[{k: t[k] for k in ("id", "invariant_id", "title", "status", "severity", "owner",
                                        "impact", "endpoint", "method", "seconds_deploy_to_proof")}
                     for t in tickets],
            scoreboard={"findings": len(tickets),
                        "resolved": sum(1 for t in tickets if t["status"] == "Resolved"),
                        "checks_run": len(self.checks), "false_positives_clean_build": self.false_positives,
                        "deploy_to_first_proof_s": first},
        )

    # -- the run ----------------------------------------------------------------------------------
    def run(self) -> str:
        try:
            snap = watcher.poll(self.client)
            self.snapshot, self.t_detect = snap, time.time()
            self._to("DETECTING", f"deploy detected: none -> {snap.version} (bundle {snap.bundle})")
            self._deploy_cycle()
            self._to("MONITORING", "waiting for the next deploy (the fix)")
            nxt = self._wait_for_deploy()
            if nxt is None:
                self._to("DONE", "no new deploy before the monitor timeout; open tickets stay open")
                return "timeout"
            self._retest_cycle(nxt)
            return "done"
        except KillSwitchEngaged as exc:
            self._to("PAUSED_SAFETY", f"stopped by the safety layer: {exc}")
            return "paused"
        except TimeoutError as exc:
            self._to("DONE", f"stopped: {exc}")
            return "timeout"

    def _context(self) -> CheckContext:
        assert self.recon is not None
        return CheckContext(self.client, Flow(self.client, load_steps(self.cfg.har)),
                            self.cfg.accounts, self.recon.amap.to_dict())

    def _deploy_cycle(self) -> None:
        self._to("MAPPING", "building the API map from the bundle, recorded journeys and logs (no spec)")
        self.recon = build_map(self.cfg, self.client)
        (self.cfg.out_dir / "openapi.json").write_text(
            json.dumps(self.recon.openapi, indent=1), encoding="utf-8")
        counts: dict[str, int] = {}
        for lab in self.recon.labels:
            counts[lab.label] = counts.get(lab.label, 0) + 1
        self._to("MAPPING", f"mapped {len(self.recon.labels)} endpoints: {counts}")
        self.ctx = self._context()

        self._to("PROPOSING", f"asking {self.llm.name} which catalogued invariants apply where")
        threshold = load_llm_config()["escalate_below_confidence"]
        proposal = propose_invariants(self.llm, self.recon.amap.to_dict(), threshold)
        prov = self.llm.provenance("propose_invariants") if hasattr(self.llm, "provenance") else {}
        self.rulebook.propose(proposal, prov)
        self.gw.audit.append("agent_action", action="propose_invariants", llm=self.llm.name,
                             prompt_version=proposal.prompt_version, provenance=prov,
                             accepted=[c.id for c in proposal.accepted],
                             rejected=len(proposal.rejected), low_confidence=proposal.low_confidence_ids)
        self.rs.set(llm={"client": self.llm.name, **prov},
                    invariants=[{**v["invariant"], "status": v["status"],
                                 "low_confidence": v["low_confidence"]}
                                for v in self.rulebook.data()["items"].values()])
        self._await_confirmation()

        confirmed = self.rulebook.confirmed()
        self._to("PLANNING", f"{len(confirmed)} confirmed invariants; one check plan each")
        planned = plan_checks(self.llm, confirmed)
        self.plans = {p.invariant_id: p for p in planned.plans}
        self.gw.audit.append("agent_action", action="plan_checks", llm=self.llm.name,
                             prompt_version=planned.prompt_version, plans=sorted(self.plans),
                             rejected=len(planned.rejected), unplanned=planned.unplanned)
        self._run_checks()

    def _await_confirmation(self) -> None:
        self._to("AWAITING_CONFIRM", "waiting for a human to confirm the proposed invariants")
        deadline = time.monotonic() + self.cfg.confirm_wait_s
        while self.rulebook.awaiting_confirmation():
            self.gw.killswitch.check()
            if time.monotonic() > deadline:
                raise TimeoutError("no human confirmed the invariants in time")
            time.sleep(0.2)
        self.rs.set(invariants=[{**v["invariant"], "status": v["status"],
                                 "low_confidence": v["low_confidence"], "decided_by": v["decided_by"]}
                                for v in self.rulebook.data()["items"].values()])

    def _run_checks(self) -> None:
        assert self.ctx is not None and self.snapshot is not None
        for inv, plan in sorted(self.plans.items()):
            self._to("CHECKING", f"{inv} {plan.check}: normal flow + one controlled variation")
            t0 = time.time()
            verdict = verify(self.ctx, plan)
            self.checks[inv] = {"check": plan.check, "endpoint": plan.endpoint,
                                "status": verdict.status, "reason": verdict.reason,
                                "trials": verdict.trials, "seconds": round(time.time() - t0, 1)}
            self.rs.set(waiting_approval=None)
            if verdict.finding:
                if self.first_proof_s is None:
                    self.first_proof_s = round(time.time() - self.t_detect, 1)
                self._to("REPORTING", f"{inv}: violated twice with a passing control; filing a ticket")
                tri = triage([verdict.finding])[0]
                self.tickets.file(tri, plan, self.snapshot.version, time.time() - self.t_detect)
        self._publish()

    def _wait_for_deploy(self) -> watcher.Snapshot | None:
        deadline = time.monotonic() + self.cfg.monitor_timeout_s
        while time.monotonic() < deadline:
            self.gw.killswitch.check()
            snap = watcher.poll(self.client)
            if snap.changed_from(self.snapshot):
                return snap
            time.sleep(self.cfg.poll_s)
        return None

    def _retest_cycle(self, snap: watcher.Snapshot) -> None:
        old = self.snapshot
        self.snapshot, self.t_detect = snap, time.time()
        self._to("DETECTING", f"deploy detected: {old.version if old else '?'} -> {snap.version} "
                              f"(bundle {'changed' if old and old.bundle != snap.bundle else 'same'})")
        previous = self.recon.amap.keys() if self.recon else set()
        self._to("MAPPING", "re-mapping to see what changed")
        self.recon = build_map(self.cfg, self.client)
        new = sorted(self.recon.amap.keys() - previous)
        self._to("MAPPING", f"{len(new)} new endpoints since the last map"
                            + (" (no new invariants run in the MVP)" if new else ""))
        self.ctx = self._context()
        self._to("RETESTING", f"re-running the stored reproduction for {len(self.tickets.open_tickets())} "
                              "open tickets")
        for t in self.tickets.open_tickets():
            result = retest_ticket(self.ctx, self.tickets, t["id"], snap.version)
            self._to("RETESTING", f"{t['id']}: {result}")
        if self.cfg.post_fix_sweep:
            self._sweep()
        left = len(self.tickets.open_tickets())
        self._to("DONE", f"{len(self.tickets.all()) - left} of {len(self.tickets.all())} tickets resolved"
                         f"; {left} still open")

    def _sweep(self) -> None:
        """Run every check once more on the new build: any finding here is a regression or a
        false positive, and is counted on the scoreboard."""
        assert self.ctx is not None
        self._to("RETESTING", "regression sweep: all invariants on the new build")
        count = 0
        for inv, plan in sorted(self.plans.items()):
            v = verify(self.ctx, plan)
            count += 1 if v.status == "finding" else 0
            self.checks[inv]["after_fix"] = v.status
        self.false_positives = count
        self._publish()
