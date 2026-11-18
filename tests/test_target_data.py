"""Defender-side checks: seed list matches the target, and generated traffic has the right shape."""

import json
from pathlib import Path

import pytest
import yaml

from target import bugs, gen_data

SEEDS = Path(__file__).resolve().parent.parent / "seeds" / "seeds.yaml"


@pytest.mark.skipif(not SEEDS.exists(), reason="seeds/ is defender-only and git-ignored")
def test_seed_list_matches_target_switches():
    seeds = yaml.safe_load(SEEDS.read_text("utf-8"))["seeds"]
    assert len(seeds) >= 15
    assert {s["id"] for s in seeds} == set(bugs.BUG_IDS)
    assert len({s["class"] for s in seeds}) >= 7


def test_generated_logs_have_active_zombie_shadow_shape():
    import random

    rows = gen_data.access_logs(90, random.Random(1))
    recent = [r for r in rows if r["ts"] >= "2026-10-20"]
    assert any(r["path"].startswith("/api/v1/") for r in recent)
    v0 = [r for r in rows if r["path"].startswith("/api/v0/")]
    assert v0 and not [r for r in v0 if r["ts"] >= "2026-10-20"]  # zombie: silent for 30 days
    assert any(r["path"] == "/internal/debug/config" for r in rows)  # shadow


def test_har_is_valid_and_covers_all_roles():
    har = gen_data.journeys()
    entries = har["log"]["entries"]
    assert len(entries) > 30
    paths = {e["request"]["url"] for e in entries}
    assert any(p.endswith("/refunds") for p in paths)
    assert all(e["response"]["status"] < 500 for e in entries)
    json.dumps(har)
    assert bugs.state.mode == "vulnerable"  # the recorder restores the default build
