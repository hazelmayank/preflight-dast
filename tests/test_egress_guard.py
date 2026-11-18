"""Build-failing guard: only preflight/safety/gateway.py may do network I/O."""

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PKG = ROOT / "preflight"
GATEWAY = PKG / "safety" / "gateway.py"

BANNED_MODULES = {
    "requests", "httpx", "urllib", "urllib3", "aiohttp", "socket", "http.client",
    "ftplib", "smtplib", "telnetlib", "websockets", "subprocess", "ctypes",
}
BANNED_CALLS = {"os.system", "os.popen", "asyncio.open_connection", "asyncio.start_server"}
DYNAMIC_IMPORTERS = {"__import__", "importlib.import_module", "import_module"}


def _banned(name: str) -> bool:
    return any(name == m or name.startswith(m + ".") for m in BANNED_MODULES)


def _dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{_dotted(node.value)}.{node.attr}"
    return ""


def scan_source(source: str) -> list[str]:
    """Return a list of egress violations found in ``source``."""
    found = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            found += [f"import {a.name}" for a in node.names if _banned(a.name)]
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if _banned(mod) or any(_banned(f"{mod}.{a.name}") for a in node.names):
                found.append(f"from {mod} import ...")
        elif isinstance(node, ast.Call):
            fn = _dotted(node.func)
            if fn in BANNED_CALLS:
                found.append(f"call {fn}")
            if fn in DYNAMIC_IMPORTERS:  # dynamic imports hide the target, so forbid them
                found.append(f"dynamic import via {fn}")
    return found


def _agent_files():
    return [p for p in PKG.rglob("*.py") if p != GATEWAY]


def test_no_network_imports_outside_gateway():
    offenders = {
        str(p.relative_to(ROOT)): v
        for p in _agent_files()
        if (v := scan_source(p.read_text("utf-8")))
    }
    assert not offenders, f"egress outside gateway.py: {offenders}"


def test_gateway_is_the_egress_point():
    assert GATEWAY.exists()
    assert "import httpx" in GATEWAY.read_text("utf-8")


def test_gateway_does_not_shell_out():
    assert not [v for v in scan_source(GATEWAY.read_text("utf-8")) if "subprocess" in v]


@pytest.mark.parametrize(
    "src",
    [
        "import requests",
        "import httpx as h",
        "from urllib.request import urlopen",
        "from urllib import parse",
        "import socket",
        "import urllib3",
        "from http import client",
        "from http.client import HTTPConnection",
        "import subprocess",
        "import os\nos.system('curl x')",
        "__import__('socket')",
        "import importlib\nimportlib.import_module('requests')",
    ],
)
def test_scanner_catches_violations(src):
    assert scan_source(src), src


@pytest.mark.parametrize("src", ["import json\nimport pathlib", "from dataclasses import dataclass"])
def test_scanner_allows_clean_code(src):
    assert scan_source(src) == []
