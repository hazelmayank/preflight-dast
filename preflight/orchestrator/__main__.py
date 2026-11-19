"""``python -m preflight.orchestrator --config demo/config.yaml``: run one release-safety loop.

A human must confirm the proposed invariants and approve reserved actions (control-room UI or the
CLIs in preflight.discovery.rulebook / preflight.safety.approval).
"""

import sys

from .factory import build


def main() -> int:
    args = sys.argv[1:]
    path = args[args.index("--config") + 1] if "--config" in args else "demo/config.yaml"
    orch = build(path)
    result = orch.run()
    print(f"run finished: {result}; state={orch.state}")
    return 0 if result == "done" else 1


if __name__ == "__main__":
    raise SystemExit(main())
