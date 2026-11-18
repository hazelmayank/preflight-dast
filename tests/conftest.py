import shutil
from pathlib import Path

import pytest

SAFETY = Path(__file__).resolve().parent.parent / "preflight" / "safety"


@pytest.fixture
def policy(tmp_path):
    """Writable copies of the policy files, so tests can tamper without touching the repo."""
    d = tmp_path / "policy"
    d.mkdir()
    for name in ("scope.yaml", "limits.yaml", "reserved_actions.yaml"):
        shutil.copy(SAFETY / name, d / name)
    return d
