"""Change watcher: notices a deploy (version change) or a changed front-end bundle."""

from __future__ import annotations

import re
from dataclasses import dataclass

from preflight.execution.client import ApiClient, Inconclusive
from preflight.recon.js_parser import bundle_hash

_SCRIPT = re.compile(r'<script[^>]+src="([^"]+)"')


@dataclass(frozen=True)
class Snapshot:
    version: str
    bundle: str  # hash of the concatenated front-end bundles

    def changed_from(self, other: Snapshot | None) -> bool:
        return other is None or (self.version, self.bundle) != (other.version, other.bundle)


def poll(client: ApiClient) -> Snapshot:
    """Read the deployed version and hash the front-end bundle(s). Two GETs through the gateway."""
    ver = client.call("GET", "/_version", label="watch: version")
    if not ver.ok or not ver.json():
        raise Inconclusive(f"version endpoint returned HTTP {ver.status}")
    page = client.call("GET", "/", label="watch: index")
    js = ""
    for src in _SCRIPT.findall(page.raw):
        js += client.call("GET", src, label=f"watch: {src}").raw
    return Snapshot(str(ver.json()["version"]), bundle_hash(js))
