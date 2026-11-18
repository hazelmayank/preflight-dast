"""Build-failing guard: agent code must never read the defender's seeds/ (or the target)."""

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PKG = ROOT / "preflight"
FORBIDDEN_IMPORTS = {"seeds", "target", "bench"}
_PATH_SEG = re.compile(r"(^|[\\/.])seeds([\\/.]|$)")


def violations(source: str) -> list[str]:
    tree = ast.parse(source)
    docstrings = {
        id(n.body[0].value)
        for n in ast.walk(tree)
        if isinstance(n, ast.Module | ast.FunctionDef | ast.ClassDef | ast.AsyncFunctionDef)
        and n.body
        and isinstance(n.body[0], ast.Expr)
        and isinstance(n.body[0].value, ast.Constant)
    }
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found += [a.name for a in node.names if a.name.split(".")[0] in FORBIDDEN_IMPORTS]
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] in FORBIDDEN_IMPORTS:
                found.append(node.module)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            if id(node) not in docstrings and _PATH_SEG.search(node.value):
                found.append(f"string {node.value!r}")
    return found


def test_preflight_never_touches_seeds_or_target():
    bad = {
        str(p.relative_to(ROOT)): v
        for p in PKG.rglob("*.py")
        if (v := violations(p.read_text("utf-8")))
    }
    assert not bad, f"agent code references defender-only material: {bad}"


def test_checker_catches_violations():
    assert violations("import seeds")
    assert violations("from seeds.bugs import X")
    assert violations("from target import app")
    assert violations("p = open('seeds/seeds.yaml')")
    assert violations("Path('..') / 'seeds'")
    assert not violations('"""mentions seeds/ in a docstring"""\nx = 1')
    assert not violations("random_seeds = [1, 2]")
