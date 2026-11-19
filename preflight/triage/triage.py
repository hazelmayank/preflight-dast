"""Triage: dedupe findings, price them in business terms, and route them to an owner."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from preflight.execution.verifier import Finding

HERE = Path(__file__).parent


@dataclass
class Triaged:
    finding: Finding
    dedupe_key: str
    severity: str
    severity_reasons: list[str]
    impact: str
    owner: dict[str, str]


def _load(name: str) -> dict[str, Any]:
    return yaml.safe_load((HERE / name).read_text(encoding="utf-8"))


def dedupe_key(f: Finding) -> str:
    return f"{f.kind}|{f.method}|{f.endpoint}"


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Keep one finding per (kind, method, endpoint); the earliest wins."""
    seen: dict[str, Finding] = {}
    for f in sorted(findings, key=lambda x: x.detected_at):
        seen.setdefault(dedupe_key(f), f)
    return list(seen.values())


def severity(f: Finding, cfg: dict[str, Any] | None = None) -> tuple[str, list[str]]:
    cfg = cfg or _load("severity.yaml")
    levels = cfg["levels"]
    lvl = levels.index(cfg["base"][f.kind])
    why = [f"base severity for {f.kind}: {levels[lvl]}"]
    money = float(f.impact.get("money_delta_inr", 0) or 0)
    if money >= cfg["money_over_inr"] and lvl < len(levels) - 1:
        lvl += 1
        why.append(f"money at risk per attempt is INR {money:,.0f} (>= {cfg['money_over_inr']:,})")
    fields = f.impact.get("fields", [])
    if any(re.search(cfg["secret_field_regex"], x, re.I) for x in fields) and lvl < len(levels) - 1:
        lvl += 1
        why.append("secrets or credentials are exposed")
    if f.impact.get("cross_tenant"):
        why.append("crosses tenant boundaries")
    return levels[lvl], why


def impact_text(f: Finding, cfg: dict[str, Any] | None = None) -> str:
    cfg = cfg or _load("severity.yaml")
    parts = []
    money = float(f.impact.get("money_delta_inr", 0) or 0)
    if money:
        n = cfg["assumed_exploits_per_day"]
        parts.append(f"INR {money:,.0f} per attempt; about INR {money * n:,.0f}/day at an assumed "
                     f"{n} attempts/day (assumption, not TBO data)")
    if f.impact.get("cross_tenant"):
        parts.append("one agency can reach another agency's data or bookings")
    if f.impact.get("privilege"):
        parts.append("a low-privilege role can perform admin-only actions")
    if f.impact.get("data_exposure"):
        parts.append("sensitive fields exposed: " + ", ".join(f.impact.get("fields", [])[:6]))
    return "; ".join(parts) or "business rule violated"


def owner_for(endpoint: str) -> dict[str, str]:
    cfg = _load("ownership.yaml")
    for rule in cfg["rules"]:
        if re.search(rule["path_regex"], endpoint):
            return {"team": rule["team"], "contact": rule["contact"]}
    return dict(cfg["default"])


def triage(findings: list[Finding]) -> list[Triaged]:
    cfg = _load("severity.yaml")
    out = []
    for f in dedupe(findings):
        sev, why = severity(f, cfg)
        out.append(Triaged(f, dedupe_key(f), sev, why, impact_text(f, cfg), owner_for(f.endpoint)))
    return out
