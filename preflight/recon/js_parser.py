"""Extract API calls from a front-end JS bundle with regexes (no JS engine).

Recognises the two common shapes:
  helper("METHOD", "/path", {a, b})                  e.g. call("POST", "/x", {email, password})
  fetch(`${API}/path`, {method: "METHOD", ...})
and a ``const API = "/api/v1"`` style prefix. Real bundlers/minifiers will need more patterns;
that is a known limit (see README).
"""

from __future__ import annotations

import hashlib
import re

from .api_map import ApiMap, normalize_js_template

_PREFIX = re.compile(r"""(?:const|let|var)\s+API\w*\s*=\s*["'`]([^"'`]+)["'`]""")
_HELPER = re.compile(
    r"""\w+\(\s*["'](GET|POST|PUT|PATCH|DELETE)["']\s*,\s*["'`]([^"'`]+)["'`]\s*(?:,\s*(\{[^}]*\}))?"""
)
_FETCH = re.compile(
    r"""fetch\(\s*(?:API\s*\+\s*)?[`"']?(?:\$\{API\})?([^`"',)]+)[`"']?\s*,\s*\{[^}]*method\s*:\s*["'](\w+)["']"""
)


def bundle_hash(js: str) -> str:
    return hashlib.sha256(js.encode()).hexdigest()[:16]


def _shorthand_fields(obj: str | None) -> list[str]:
    if not obj:
        return []
    return [f.split(":")[0].strip() for f in obj.strip("{} ").split(",") if f.strip()]


def add_js_to_map(amap: ApiMap, js: str) -> int:
    """Add endpoints found in ``js``. Returns how many calls were recognised."""
    prefix = (m.group(1) if (m := _PREFIX.search(js)) else "").rstrip("/")
    found = 0
    for method, path, body in _HELPER.findall(js):
        full = path if path.startswith(prefix) or not prefix else prefix + path
        if not full.startswith("/"):
            continue
        ep = amap.endpoint(method, normalize_js_template(full))
        ep.sources.add("js")
        for q in re.findall(r"[?&](\w+)=\$\{", path):
            ep.query_params.setdefault(q, set())
        for f in _shorthand_fields(body):
            ep.body_fields.setdefault(f, None)
        found += 1
    for path, method in _FETCH.findall(js):
        full = path if path.startswith("/api") or not prefix else prefix + path
        if full.startswith("/"):
            amap.endpoint(method.upper(), normalize_js_template(full)).sources.add("js")
            found += 1
    return found
