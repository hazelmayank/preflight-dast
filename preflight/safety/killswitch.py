"""Global kill switch: an in-memory flag plus an on-disk file (default ``out/KILL``).

Either one engages it. The gateway checks it before every send, so touching the file from
another terminal (or calling ``engage``) halts a run at the next request.

Releasing is a human action (``human_release``); a test forbids agent code from calling it.
"""

from __future__ import annotations

import json
import sys
import threading
import time
from pathlib import Path


class KillSwitchEngaged(RuntimeError):
    """Raised when a request is attempted while the kill switch is engaged."""


class KillSwitch:
    def __init__(self, flag_path: Path | str):
        self._path = Path(flag_path)
        self._engaged = False
        self._reason = ""
        self._lock = threading.Lock()

    @property
    def path(self) -> Path:
        return self._path

    def engage(self, reason: str, by: str = "system") -> None:
        """Stop everything. The in-memory flag is set even if the file cannot be written."""
        with self._lock:
            self._engaged = True
            self._reason = reason
            try:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                self._path.write_text(
                    json.dumps({"reason": reason, "by": by, "ts": time.time()}), encoding="utf-8"
                )
            except OSError:
                pass

    def is_engaged(self) -> bool:
        return self._engaged or self._path.exists()

    def reason(self) -> str:
        if self._engaged:
            return self._reason
        try:
            return json.loads(self._path.read_text(encoding="utf-8")).get("reason", "KILL file")
        except (OSError, ValueError):
            return "KILL file present"

    def check(self) -> None:
        if self.is_engaged():
            raise KillSwitchEngaged(self.reason())

    def human_release(self, by: str) -> None:
        """Clear the switch. Humans only (CLI or operator UI)."""
        if not by.strip():
            raise ValueError("a named human must release the kill switch")
        with self._lock:
            self._engaged = False
            self._reason = ""
            self._path.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    """CLI: ``python -m preflight.safety.killswitch engage|release|status [--out out]``."""
    args = list(sys.argv[1:] if argv is None else argv)
    out = Path(args[args.index("--out") + 1]) if "--out" in args else Path("out")
    ks = KillSwitch(out / "KILL")
    cmd = args[0] if args else "status"
    if cmd == "engage":
        ks.engage("operator CLI", by="operator")
    elif cmd == "release":
        ks.human_release(by="operator")
    print("ENGAGED: " + ks.reason() if ks.is_engaged() else "clear")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
