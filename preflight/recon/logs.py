"""Read JSONL access logs into per-endpoint traffic statistics (counts, last seen)."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .api_map import ApiMap, path_params, templatize


@dataclass
class Traffic:
    count: int = 0
    last_seen: str = ""
    sources: set[str] | None = None


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def read_logs(path: Path | str) -> dict[str, Traffic]:
    """Map ``"METHOD /templated/path"`` -> Traffic, plus example ids via ``add_logs_to_map``."""
    stats: dict[str, Traffic] = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        key = f"{row['method']} {templatize(row['path'])}"
        t = stats.setdefault(key, Traffic(sources=set()))
        t.count += 1
        t.last_seen = max(t.last_seen, row["ts"])
        t.sources.add(row.get("source", ""))
    return stats


def add_logs_to_map(amap: ApiMap, path: Path | str) -> None:
    """Add endpoints seen only in traffic (zombie / shadow candidates) with example ids."""
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        tmpl = templatize(row["path"])
        ep = amap.endpoint(row["method"], tmpl)
        ep.sources.add("logs")
        ep.statuses.add(row["status"])
        for tseg, aseg in zip(tmpl.split("/"), row["path"].split("?")[0].split("/"), strict=False):
            if tseg.startswith("{") and tseg[1:-1] in path_params(tmpl) and len(ep.examples.get(
                    tseg[1:-1], ())) < 8:
                ep.examples.setdefault(tseg[1:-1], set()).add(aseg)


def days_between(newer: str, older: str) -> float:
    return (_parse(newer) - _parse(older)).total_seconds() / 86400
