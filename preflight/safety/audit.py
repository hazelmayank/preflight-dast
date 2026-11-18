"""Hash-chained audit log (``audit.jsonl``) plus secret redaction.

Every line holds ``seq``, ``ts``, ``event``, ``data``, ``prev`` and ``hash`` where
``hash = sha256(prev + canonical_json(seq, ts, event, data))``. Editing, deleting or reordering
any line breaks the chain, which ``verify`` detects.

Note: this module avoids ``urllib`` on purpose. URL handling belongs to the gateway.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

GENESIS = "0" * 64
REDACTED = "[REDACTED]"

_SENSITIVE_KEY = re.compile(
    r"password|passwd|pwd|secret|token|authorization|api[_-]?key|cookie|cvv|"
    r"card[_-]?number|signature|credential|session",
    re.IGNORECASE,
)
_BEARER = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{6,}")
_KV = re.compile(
    r"(?i)((?:password|passwd|pwd|secret|token|api[_-]?key|signature)[\"']?\s*[=:]\s*[\"']?)"
    r"[^&\s\"',}]+"
)
_URL_QUERY = re.compile(
    r"(?i)([?&](?:[a-z_]*(?:token|key|secret|password|sig|signature)[a-z_]*)=)[^&#\s]+"
)


def redact_headers(headers: dict[str, Any]) -> dict[str, Any]:
    return {k: (REDACTED if _SENSITIVE_KEY.search(k) else _scrub(str(v))) for k, v in headers.items()}


def redact_json(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {
            k: (REDACTED if _SENSITIVE_KEY.search(str(k)) else redact_json(v))
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [redact_json(v) for v in obj]
    if isinstance(obj, str):
        return _scrub(obj)
    return obj


def redact_text(text: str, limit: int = 1000) -> str:
    """Redact a body (JSON or form/plain text), then truncate for the log."""
    try:
        out = json.dumps(redact_json(json.loads(text)), separators=(",", ":"))
    except ValueError:
        out = _scrub(text)
    return out if len(out) <= limit else out[:limit] + f"...[+{len(out) - limit} chars]"


def redact_url(url: str) -> str:
    return _URL_QUERY.sub(lambda m: m.group(1) + REDACTED, url)


def _scrub(s: str) -> str:
    s = _BEARER.sub(lambda m: f"{m.group(1)} {REDACTED}", s)
    return _KV.sub(lambda m: m.group(1) + REDACTED, s)


def _digest(prev: str, seq: int, ts: float, event: str, data: dict[str, Any]) -> str:
    body = json.dumps(
        {"seq": seq, "ts": ts, "event": event, "data": data},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256((prev + body).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Verification:
    ok: bool
    entries: int
    error: str = ""


class AuditLog:
    def __init__(self, path: Path | str, wall_clock=time.time):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._clock = wall_clock
        self._lock = threading.Lock()
        self._seq, self._prev = self._resume()

    def _resume(self) -> tuple[int, str]:
        if not self.path.exists():
            return 0, GENESIS
        last = None
        with self.path.open(encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    last = line
        if last is None:
            return 0, GENESIS
        rec = json.loads(last)
        return rec["seq"], rec["hash"]

    def append(self, event: str, **data: Any) -> dict[str, Any]:
        with self._lock:
            seq, ts = self._seq + 1, round(self._clock(), 6)
            data = json.loads(json.dumps(data, default=str))  # normalise to plain JSON
            digest = _digest(self._prev, seq, ts, event, data)
            rec = {"seq": seq, "ts": ts, "event": event, "data": data,
                   "prev": self._prev, "hash": digest}
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, separators=(",", ":")) + "\n")
            self._seq, self._prev = seq, digest
            return rec

    @staticmethod
    def verify(path: Path | str) -> Verification:
        prev, count = GENESIS, 0
        p = Path(path)
        if not p.exists():
            return Verification(True, 0)
        with p.open(encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                    count += 1
                    if rec["seq"] != count:
                        return Verification(False, count, f"seq gap at line {count}")
                    if rec["prev"] != prev:
                        return Verification(False, count, f"broken link at seq {count}")
                    want = _digest(prev, rec["seq"], rec["ts"], rec["event"], rec["data"])
                    if rec["hash"] != want:
                        return Verification(False, count, f"hash mismatch at seq {count}")
                    prev = rec["hash"]
                except (ValueError, KeyError) as exc:
                    return Verification(False, count, f"unreadable entry {count}: {exc}")
        return Verification(True, count)
