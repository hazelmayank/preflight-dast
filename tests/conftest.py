import shutil
from pathlib import Path

import pytest

SAFETY = Path(__file__).resolve().parent.parent / "preflight" / "safety"


@pytest.fixture
def policy(tmp_path):
    """Writable copies of the policy files, so tests can tamper without touching the repo."""
    d = tmp_path / "policy"
    d.mkdir()
    for name in ("scope.yaml", "limits.yaml", "reserved_actions.yaml"):
        shutil.copy(SAFETY / name, d / name)
    return d


@pytest.fixture(scope="session")
def api_map_dict(tmp_path_factory):
    """The API map rebuilt with no spec: HAR + JS bundle + 90-day logs of the synthetic target."""
    import json
    import random

    from fastapi.testclient import TestClient

    from preflight.recon.api_map import ApiMap
    from preflight.recon.har_parser import add_to_map, load_steps
    from preflight.recon.js_parser import add_js_to_map
    from preflight.recon.logs import add_logs_to_map
    from target import gen_data
    from target.app import app

    d = tmp_path_factory.mktemp("map")
    (d / "j.har").write_text(json.dumps(gen_data.journeys()))
    rows = gen_data.access_logs(90, random.Random(20261119))
    (d / "l.jsonl").write_text("\n".join(json.dumps(r) for r in rows))
    amap = ApiMap()
    with TestClient(app) as c:
        add_js_to_map(amap, c.get("/static/app.js").text)
    add_to_map(amap, load_steps(d / "j.har"))
    add_logs_to_map(amap, d / "l.jsonl")
    return amap.to_dict()
