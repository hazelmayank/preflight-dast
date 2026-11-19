"""Label every endpoint active / zombie / shadow by comparing the map with 30/90-day logs.

* zombie: seen in the 90-day logs but silent for the last 30 days (still routable, unmaintained);
* shadow: live traffic but absent from the client surface (front-end JS and recorded journeys),
  so nobody documents or reviews it;
* active: part of the client surface (and, if logs exist, seen recently).
Labels are evidence-based; thresholds live in the call, not in code literals elsewhere.
"""

from __future__ import annotations

from dataclasses import dataclass

from preflight.recon.api_map import ApiMap
from preflight.recon.logs import Traffic

RECENT_DAYS = 30.0


@dataclass(frozen=True)
class Label:
    endpoint: str
    label: str  # active | zombie | shadow
    reason: str
    hits_30d: int
    hits_90d: int
    last_seen: str


def classify(amap: ApiMap, logs_30d: dict[str, Traffic], logs_90d: dict[str, Traffic]) -> list[Label]:
    out = []
    for key, ep in sorted(amap.endpoints.items()):
        h30 = logs_30d.get(key, Traffic()).count
        t90 = logs_90d.get(key, Traffic())
        client_known = bool(ep.sources & {"js", "har"})
        if t90.count and not h30:
            label, why = "zombie", f"{t90.count} hits in 90d, none in the last {RECENT_DAYS:.0f}d"
        elif not client_known:
            label, why = "shadow", "live traffic but not in the front-end bundle or recorded journeys"
        else:
            label = "active"
            why = f"{h30} hits in 30d" if h30 else "in client surface; no recent traffic sample"
        out.append(Label(key, label, why, h30, t90.count, t90.last_seen))
    return out
