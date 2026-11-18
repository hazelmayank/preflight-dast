"""Deploy state and the bug switchboard for the synthetic target.

``vulnerable`` mode enables every bug in BUG_IDS; ``fixed`` mode enables none. A deploy can also
patch individual bugs (``patched``) to simulate a partial fix, which is what retest exercises.
The agent never sees this module; it only sees HTTP behaviour.
"""

from __future__ import annotations

from dataclasses import dataclass, field

BUG_IDS = [f"S{i:02d}" for i in range(1, 21)]


@dataclass
class DeployState:
    version: str = "v1.0.0"
    mode: str = "vulnerable"  # "vulnerable" | "fixed"
    patched: set[str] = field(default_factory=set)
    deploys: int = 0


state = DeployState()


def vulnerable(bug_id: str) -> bool:
    """True when ``bug_id`` is live in the currently deployed build."""
    assert bug_id in BUG_IDS, bug_id
    return state.mode == "vulnerable" and bug_id not in state.patched


def deploy(version: str, mode: str, patched: list[str] | None = None) -> None:
    if mode not in ("vulnerable", "fixed"):
        raise ValueError("mode must be 'vulnerable' or 'fixed'")
    unknown = set(patched or []) - set(BUG_IDS)
    if unknown:
        raise ValueError(f"unknown bug ids: {sorted(unknown)}")
    state.version, state.mode, state.patched = version, mode, set(patched or [])
    state.deploys += 1
