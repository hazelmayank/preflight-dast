"""Anthropic Messages API client. Opt-in; every call goes through the gateway's LLM channel.

The gateway refuses it unless ``llm_hosts`` in scope.yaml names ``api.anthropic.com``. Prompts carry
the inferred API map of the synthetic target; nothing else leaves the machine.
"""

from __future__ import annotations

import json
import re
from typing import Any

from preflight.safety.gateway import Gateway

from .base import LLMError

URL = "https://api.anthropic.com/v1/messages"
_FENCE = re.compile(r"^```(?:json)?\s*|\s*```$")


class AnthropicLLM:
    name = "anthropic"

    def __init__(self, gateway: Gateway, api_key: str, models: dict[str, str], max_tokens: int = 4000):
        self._gw, self._key, self._models, self._max = gateway, api_key, models, max_tokens

    def complete_json(self, task: str, system: str, payload: dict[str, Any], tier: str = "small",
                      ) -> dict[str, Any]:
        resp = self._gw.send(
            "POST", URL, channel="llm", actor="llm", purpose=f"{task}:{tier}",
            headers={"x-api-key": self._key, "anthropic-version": "2023-06-01"},
            json_body={
                "model": self._models[tier], "max_tokens": self._max,
                "system": system + "\nReply with one JSON object only, no prose.",
                "messages": [{"role": "user", "content": json.dumps(payload)}],
            },
        )
        if resp.status != 200:
            raise LLMError(f"LLM call failed with HTTP {resp.status}")
        text = "".join(b.get("text", "") for b in resp.json().get("content", []))
        try:
            return json.loads(_FENCE.sub("", text.strip()))
        except ValueError as exc:
            raise LLMError("LLM did not return valid JSON") from exc
