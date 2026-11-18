"""Build-failing guard: agent code must not approve actions or release the kill switch."""

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PKG = ROOT / "preflight"
HUMAN_ONLY = {"approve", "human_release"}
ALLOWED = {PKG / "safety" / "approval.py", PKG / "safety" / "killswitch.py"}
ALLOWED_DIRS = {PKG / "ui"}  # operator UI: a human clicks the button


def human_calls(source: str) -> list[str]:
    return [
        n.func.attr
        for n in ast.walk(ast.parse(source))
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr in HUMAN_ONLY
    ]


def test_no_auto_approve_or_release():
    bad = {}
    for p in PKG.rglob("*.py"):
        if p in ALLOWED or any(d in p.parents for d in ALLOWED_DIRS):
            continue
        if calls := human_calls(p.read_text("utf-8")):
            bad[str(p.relative_to(ROOT))] = calls
    assert not bad, f"agent code calls human-only actions: {bad}"


def test_checker_catches_calls():
    assert human_calls("queue.approve('x', 'me')")
    assert human_calls("ks.human_release('me')")
    assert not human_calls("queue.pending()")
