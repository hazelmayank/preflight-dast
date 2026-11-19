"""Build an Orchestrator from a config file: gateway, LLM client (per llm.yaml), state."""

from __future__ import annotations

import os
from pathlib import Path

from preflight.llm import LLMClient, LLMError, RecordedLLM, load_llm_config
from preflight.safety.gateway import Gateway

from .config import Config, load_config
from .machine import Orchestrator


def make_llm(cfg: Config, gateway: Gateway) -> LLMClient:
    conf = load_llm_config()
    if conf["provider"] == "recorded":
        return RecordedLLM(cfg.recordings_dir)
    if conf["provider"] == "anthropic":
        from preflight.llm.anthropic import AnthropicLLM

        key = os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            raise LLMError("provider is 'anthropic' but ANTHROPIC_API_KEY is not set")
        return AnthropicLLM(gateway, key, conf["models"], conf.get("max_tokens", 4000))
    raise LLMError(f"unknown provider {conf['provider']!r}")


def build(config_path: Path | str) -> Orchestrator:
    cfg = load_config(config_path)
    gateway = Gateway(out_dir=cfg.out_dir)
    return Orchestrator(cfg, gateway, make_llm(cfg, gateway))
