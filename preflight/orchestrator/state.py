"""Run state shared with the control-room UI: ``out/state.json`` (atomic writes, thread-safe)."""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import Any


class RunState:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self.data: dict[str, Any] = {
            "state": "IDLE", "version": None, "started": time.time(), "events": [], "inventory": [],
            "llm": {}, "invariants": [], "checks": {}, "tickets": [], "scoreboard": {},
            "safety": {}, "waiting_approval": None,
        }
        self.flush()

    def event(self, state: str, msg: str) -> None:
        with self._lock:
            self.data["state"] = state
            self.data["events"].append({"ts": time.time(), "state": state, "msg": msg})
        self.flush()

    def set(self, **kv: Any) -> None:
        with self._lock:
            self.data.update(kv)
        self.flush()

    def flush(self) -> None:
        with self._lock:
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.data, indent=1, default=str), encoding="utf-8")
            os.replace(tmp, self.path)
