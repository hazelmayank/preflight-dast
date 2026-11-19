"""Emit an OpenAPI 3 document from the inferred map (no spec was given as input)."""

from __future__ import annotations

from typing import Any

from preflight.recon.api_map import ApiMap, path_params

from .classifier import Label


def _type(value: Any) -> str:
    return {bool: "boolean", int: "integer", float: "number", str: "string"}.get(type(value), "string")


def emit_openapi(amap: ApiMap, labels: list[Label], title: str = "Inferred API") -> dict[str, Any]:
    by_key = {lab.endpoint: lab for lab in labels}
    paths: dict[str, dict[str, Any]] = {}
    for key, ep in sorted(amap.endpoints.items()):
        params = [{"name": p, "in": "path", "required": True, "schema": {"type": "string"}}
                  for p in path_params(ep.path)]
        params += [{"name": q, "in": "query", "schema": {"type": "string"}} for q in ep.query_params]
        op: dict[str, Any] = {
            "parameters": params,
            "responses": {str(s): {"description": ""} for s in sorted(ep.statuses) or [200]},
            "x-preflight": {"label": by_key[key].label if key in by_key else "unknown",
                            "sources": sorted(ep.sources)},
        }
        if ep.auth_seen:
            op["security"] = [{"bearerAuth": []}]
        if ep.body_fields:
            op["requestBody"] = {"content": {"application/json": {"schema": {
                "type": "object",
                "properties": {k: {"type": _type(v)} for k, v in ep.body_fields.items()}}}}}
        paths.setdefault(ep.path, {})[ep.method.lower()] = op
    return {"openapi": "3.0.3", "info": {"title": title, "version": "inferred"}, "paths": paths,
            "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}}}
