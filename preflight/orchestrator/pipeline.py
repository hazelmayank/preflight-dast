"""Recon + inventory step: build the API map with no spec and label every endpoint."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from preflight.execution.client import ApiClient
from preflight.inventory.classifier import Label, classify
from preflight.inventory.openapi_emitter import emit_openapi
from preflight.recon.api_map import ApiMap
from preflight.recon.har_parser import Step, add_to_map, load_steps
from preflight.recon.js_parser import add_js_to_map
from preflight.recon.logs import add_logs_to_map, read_logs

from .config import Config

_SCRIPT = re.compile(r'<script[^>]+src="([^"]+)"')


@dataclass
class Recon:
    amap: ApiMap
    labels: list[Label]
    openapi: dict[str, Any]
    steps: list[Step]


def build_map(cfg: Config, client: ApiClient) -> Recon:
    """Fetch the front-end bundle through the gateway, read recorded journeys and logs, classify."""
    amap = ApiMap()
    page = client.call("GET", "/", label="recon: index")
    for src in _SCRIPT.findall(page.raw):
        add_js_to_map(amap, client.call("GET", src, label=f"recon: {src}").raw)
    steps = load_steps(cfg.har)
    add_to_map(amap, steps)
    add_logs_to_map(amap, cfg.logs_90d)
    labels = classify(amap, read_logs(cfg.logs_30d), read_logs(cfg.logs_90d))
    return Recon(amap, labels, emit_openapi(amap, labels, "Inferred API"), steps)
