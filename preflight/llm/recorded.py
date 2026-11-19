"""Recorded-replay LLM: serves saved responses from ``demo/recordings/<task>.json``.

No key and no network. Each recording is ``{"source": ..., "model": ..., "response": {...}}``; the
``source`` field says whether it came from a live model or is a hand-authored fixture, and the
orchestrator shows it in the UI and audit log so a replay is never passed off as a live call.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .base import LLMError


class RecordedLLM:
    name = "recorded-replay"

    def __init__(self, directory: Path | str):
        self._dir = Path(directory)

    def _load(self, task: str) -> dict[str, Any]:
        path = self._dir / f"{task}.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise LLMError(f"no usable recording for task {task!r} in {self._dir}") from exc
        if not isinstance(data, dict) or not isinstance(data.get("response"), dict):
            raise LLMError(f"recording {path.name} must contain a 'response' object")
        return data

    def complete_json(self, task: str, system: str, payload: dict[str, Any], tier: str = "small",
                      ) -> dict[str, Any]:
        return self._load(task)["response"]

    def provenance(self, task: str) -> dict[str, str]:
        d = self._load(task)
        return {"source": str(d.get("source", "unknown")), "model": str(d.get("model", "unknown")),
                "prompt_version": str(d.get("prompt_version", "unknown"))}
