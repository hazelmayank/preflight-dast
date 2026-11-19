"""With no spec, recon must rebuild >=90% of the target's routes and label zombie/shadow correctly."""

import json
import random
import re

import pytest
from fastapi.testclient import TestClient

from preflight.inventory.classifier import classify
from preflight.inventory.openapi_emitter import emit_openapi
from preflight.recon.api_map import ApiMap
from preflight.recon.har_parser import add_to_map, load_steps
from preflight.recon.js_parser import add_js_to_map
from preflight.recon.logs import add_logs_to_map, read_logs
from target import gen_data
from target.app import app

META = {"/", "/_version", "/_deploy", "/static/app.js"}  # not part of the business API


def _norm(path: str) -> str:
    return re.sub(r"\{[^}]+\}", "{}", path)


def _truth() -> set[str]:
    return {
        f"{m} {_norm(r.path)}"
        for r in app.routes
        if hasattr(r, "methods") and r.path not in META
        for m in r.methods - {"HEAD", "OPTIONS"}
    }


@pytest.fixture(scope="module")
def recon(tmp_path_factory):
    d = tmp_path_factory.mktemp("recon")
    (d / "j.har").write_text(json.dumps(gen_data.journeys()))
    rows = gen_data.access_logs(90, random.Random(20261119))
    cutoff = "2026-10-20"
    (d / "l90.jsonl").write_text("\n".join(json.dumps(r) for r in rows))
    (d / "l30.jsonl").write_text("\n".join(json.dumps(r) for r in rows if r["ts"] >= cutoff))

    amap = ApiMap()
    with TestClient(app) as c:
        js = c.get("/static/app.js").text
    add_js_to_map(amap, js)
    add_to_map(amap, load_steps(d / "j.har"))
    add_logs_to_map(amap, d / "l90.jsonl")
    labels = classify(amap, read_logs(d / "l30.jsonl"), read_logs(d / "l90.jsonl"))
    return amap, {x.endpoint: x.label for x in labels}


def test_recon_rebuilds_at_least_90_percent_of_routes(recon):
    amap, _ = recon
    found = {_norm_key(k) for k in amap.endpoints}
    truth = _truth()
    coverage = len(truth & found) / len(truth)
    assert coverage >= 0.9, f"coverage {coverage:.0%}; missing {sorted(truth - found)}"


def _norm_key(key: str) -> str:
    method, path = key.split(" ", 1)
    return f"{method} {_norm(path)}"


def test_zombie_and_shadow_routes_are_labelled(recon):
    _, labels = recon
    assert labels["GET /api/v0/bookings/{booking_id}"] == "zombie"
    assert labels["GET /internal/debug/config"] == "shadow"
    assert labels["POST /webhooks/supplier"] == "shadow"
    assert labels["GET /api/v1/search"] == "active"
    assert labels["POST /api/v1/bookings/{booking_id}/pay"] == "active"


def test_only_legacy_and_internal_routes_are_not_active(recon):
    _, labels = recon
    odd = {k for k, v in labels.items() if v != "active"}
    assert odd == {"GET /api/v0/bookings/{booking_id}", "GET /internal/debug/config",
                   "POST /webhooks/supplier"}


def test_openapi_emitted_from_map(recon):
    amap, _ = recon
    labels = classify(amap, {}, {})
    spec = emit_openapi(amap, labels)
    assert spec["openapi"].startswith("3.") and "/api/v1/search" in spec["paths"]
    assert "x-preflight" in spec["paths"]["/api/v1/search"]["get"]
