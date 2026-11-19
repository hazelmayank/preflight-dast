"""Run configuration (YAML). Paths are resolved relative to the repo root (config's parent dir)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from preflight.execution.oracle import Account


@dataclass
class Config:
    root: Path
    base_url: str
    har: Path
    logs_30d: Path
    logs_90d: Path
    accounts: list[Account]
    out_dir: Path
    recordings_dir: Path
    approval_wait_s: float = 300.0
    confirm_wait_s: float = 300.0
    poll_s: float = 1.0
    monitor_timeout_s: float = 300.0
    post_fix_sweep: bool = True


def load_config(path: Path | str) -> Config:
    p = Path(path).resolve()
    root = p.parent.parent
    raw = yaml.safe_load(p.read_text(encoding="utf-8"))

    def rel(x: str) -> Path:
        return (root / x).resolve()

    return Config(
        root=root, base_url=raw["target"]["base_url"], har=rel(raw["inputs"]["har"]),
        logs_30d=rel(raw["inputs"]["logs_30d"]), logs_90d=rel(raw["inputs"]["logs_90d"]),
        accounts=[Account(**a) for a in raw["accounts"]], out_dir=rel(raw.get("out_dir", "out")),
        recordings_dir=rel(raw.get("recordings_dir", "demo/recordings")),
        approval_wait_s=float(raw.get("approval_wait_seconds", 300)),
        confirm_wait_s=float(raw.get("confirm_wait_seconds", 300)),
        poll_s=float(raw.get("poll_seconds", 1)),
        monitor_timeout_s=float(raw.get("monitor_timeout_seconds", 300)),
        post_fix_sweep=bool(raw.get("post_fix_sweep", True)),
    )
