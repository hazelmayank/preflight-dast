"""The rulebook: invariants proposed for this run and which a human has confirmed.

Confirmation is a human action. ``confirm_invariants`` confirms every proposed invariant that is
not low-confidence in one go ("a human confirms the set once"); low-confidence ones sit in a queue
and need ``confirm_low_confidence`` one by one. ``tests/test_no_auto_approve.py`` fails the build
if agent code calls any of these.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

from preflight.safety.approval import require_human

from .invariant_schema import InvariantCandidate
from .invariants import Proposal

PROPOSED, CONFIRMED, REJECTED = "proposed", "confirmed", "rejected"


class Rulebook:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    # -- agent side ---------------------------------------------------------------------------
    def propose(self, proposal: Proposal, provenance: dict[str, str] | None = None) -> None:
        low = set(proposal.low_confidence_ids)
        self._save({
            "provenance": provenance or {}, "prompt_version": proposal.prompt_version,
            "llm": proposal.llm, "rejected": proposal.rejected,
            "items": {c.id: {"invariant": c.model_dump(), "status": PROPOSED,
                             "low_confidence": c.id in low, "decided_by": None, "decided": None}
                      for c in proposal.accepted},
        })

    def data(self) -> dict[str, Any]:
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {"items": {}, "rejected": [], "provenance": {}}

    def awaiting_confirmation(self) -> list[str]:
        return [i for i, v in self.data()["items"].items() if v["status"] == PROPOSED]

    def low_confidence_queue(self) -> list[str]:
        return [i for i, v in self.data()["items"].items()
                if v["status"] == PROPOSED and v["low_confidence"]]

    def confirmed(self) -> list[InvariantCandidate]:
        return [InvariantCandidate.model_validate(v["invariant"])
                for _, v in sorted(self.data()["items"].items()) if v["status"] == CONFIRMED]

    # -- human side ---------------------------------------------------------------------------
    def confirm_invariants(self, by: str) -> list[str]:
        """Confirm every proposed, non-low-confidence invariant. Returns the confirmed ids."""
        require_human(by)
        d = self.data()
        done = []
        for inv_id, v in d["items"].items():
            if v["status"] == PROPOSED and not v["low_confidence"]:
                self._decide(v, CONFIRMED, by)
                done.append(inv_id)
        self._save(d)
        return done

    def confirm_low_confidence(self, inv_id: str, by: str) -> None:
        require_human(by)
        self._set(inv_id, CONFIRMED, by, need_low=True)

    def reject_invariant(self, inv_id: str, by: str) -> None:
        require_human(by)
        self._set(inv_id, REJECTED, by)

    # -- storage ------------------------------------------------------------------------------
    def _set(self, inv_id: str, status: str, by: str, need_low: bool = False) -> None:
        d = self.data()
        v = d["items"].get(inv_id)
        if v is None or v["status"] != PROPOSED or (need_low and not v["low_confidence"]):
            raise KeyError(f"{inv_id} is not awaiting that decision")
        self._decide(v, status, by)
        self._save(d)

    @staticmethod
    def _decide(v: dict[str, Any], status: str, by: str) -> None:
        v.update(status=status, decided_by=by, decided=time.time())

    def _save(self, data: dict[str, Any]) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=1), encoding="utf-8")
        os.replace(tmp, self.path)
