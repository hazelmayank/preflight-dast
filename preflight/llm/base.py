"""LLM client interface and model-routing config."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol

import yaml

LLM_CONFIG = Path(__file__).with_name("llm.yaml")


class LLMError(RuntimeError):
    pass


class LLMClient(Protocol):
    name: str

    def complete_json(self, task: str, system: str, payload: dict[str, Any], tier: str = "small",
                      ) -> dict[str, Any]:
        """Return a JSON object. ``tier`` is "small" (default path) or "large" (escalation)."""
        ...


def load_llm_config(path: Path | str = LLM_CONFIG) -> dict[str, Any]:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))
