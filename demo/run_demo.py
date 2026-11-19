"""``make demo``: the whole loop against our own synthetic target, offline.

deploy v1.0.0 (vulnerable) -> detect -> map -> propose (recorded replay) -> human confirms ->
checks -> verify twice with a control -> tickets -> deploy the fix -> detect -> retest -> auto-close.

Lives outside preflight/ on purpose: it starts processes and plays the human/CI roles. The scripted
operator is named ``demo-operator`` and everything it does is shown on screen. Use ``--manual`` to
decide yourself in the UI instead.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from bench.score import score, write_report  # noqa: E402
from preflight.discovery.rulebook import Rulebook  # noqa: E402
from preflight.orchestrator.factory import build  # noqa: E402
from preflight.safety.approval import ApprovalQueue  # noqa: E402
from target import gen_data  # noqa: E402
from target.store import DEPLOY_TOKEN  # noqa: E402

TARGET = "http://127.0.0.1:8000"
OPERATOR = "demo-operator"


def say(who: str, msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {who:<10} {msg}", flush=True)


def deploy(version: str, mode: str, reset: bool) -> None:
    r = httpx.post(f"{TARGET}/_deploy", headers={"x-deploy-token": DEPLOY_TOKEN}, timeout=10,
                   json={"version": version, "mode": mode, "reset": reset})
    r.raise_for_status()


def wait_up(url: str, seconds: float = 20) -> None:
    end = time.time() + seconds
    while time.time() < end:
        try:
            if httpx.get(url, timeout=1).status_code < 500:
                return
        except httpx.HTTPError:
            time.sleep(0.2)
    raise SystemExit(f"{url} did not come up")


def operator(out: Path, stop: threading.Event, counts: dict) -> None:
    """Stand-in for the human: confirms the invariants once, approves reserved actions."""
    book, queue, confirmed = Rulebook(out / "rulebook.json"), ApprovalQueue(out / "approvals.json"), False
    while not stop.is_set():
        if not confirmed and book.awaiting_confirmation():
            time.sleep(2)  # let the UI show the proposals first
            ids = book.confirm_invariants(OPERATOR)
            for low in book.low_confidence_queue():
                book.confirm_low_confidence(low, OPERATOR)
                ids.append(low + " (low confidence)")
            say("operator", f"confirmed invariants: {', '.join(ids)}")
            confirmed = True
        for rec in queue.pending():
            try:
                queue.approve(rec["id"], OPERATOR)
                counts["approved"] += 1
            except (KeyError, PermissionError):
                pass
        time.sleep(0.15)


def developer(orch, delay: float) -> None:
    while orch.state != "MONITORING":
        time.sleep(0.2)
    say("developer", f"fix ready; deploying v1.1.0 in {delay:.0f}s")
    time.sleep(delay)
    deploy("v1.1.0", "fixed", reset=False)
    say("developer", "v1.1.0 deployed")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--manual", action="store_true", help="no scripted operator; use the UI")
    ap.add_argument("--keep-alive", action="store_true", help="keep the UI up after the run")
    ap.add_argument("--ui-port", type=int, default=8001)
    args = ap.parse_args()

    out = ROOT / "out"
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir()
    os.chdir(ROOT)
    gen_data.main()
    env = {**os.environ, "PREFLIGHT_OUT": str(out)}
    procs = [
        subprocess.Popen([sys.executable, "-m", "uvicorn", "target.app:app", "--host", "127.0.0.1",
                          "--port", "8000", "--log-level", "warning"]),
        subprocess.Popen([sys.executable, "-m", "uvicorn", "preflight.ui.server:app", "--host",
                          "127.0.0.1", "--port", str(args.ui_port), "--log-level", "warning"], env=env),
    ]
    code = 1
    try:
        wait_up(f"{TARGET}/_version")
        wait_up(f"http://127.0.0.1:{args.ui_port}/api/state")
        say("ui", f"control room: http://127.0.0.1:{args.ui_port}")
        deploy("v1.0.0", "vulnerable", reset=True)
        say("ci", "simulated deploy: v1.0.0")

        orch = build(ROOT / "demo" / "config.yaml")
        stop, counts = threading.Event(), {"approved": 0}
        if not args.manual:
            threading.Thread(target=operator, args=(out, stop, counts), daemon=True).start()
            say("operator", f"scripted stand-in for the human is '{OPERATOR}' (use --manual to decide yourself)")
        threading.Thread(target=developer, args=(orch, 3), daemon=True).start()

        t0 = time.time()
        result = orch.run()
        elapsed = time.time() - t0
        stop.set()

        res = score(out)
        write_report(res)
        saf = orch.safety_summary()
        tickets = orch.tickets.all()
        resolved = sum(1 for t in tickets if t["status"] == "Resolved")
        print("\n=== SCOREBOARD " + "=" * 52)
        print(f" result                         {result} in {elapsed:.0f}s (limit 300s)")
        print(f" seeded issues found            {res['found']} / {res['total']}  ({', '.join(res['found_ids'])})")
        print(f" findings / tickets resolved    {len(tickets)} / {resolved}")
        print(f" false positives (fixed build)  {orch.false_positives}")
        print(f" deploy -> first proof          {res['deploy_to_first_proof_s']} s")
        print(f" requests sent / held           {saf['requests_sent']} / {saf['held_for_approval']}"
              f" (approvals by {OPERATOR}: {counts['approved']})")
        print(f" out-of-scope requests sent     {saf['out_of_scope_sent']}")
        print(f" audit chain valid              {saf['audit_chain_ok']} ({saf['audit_entries']} entries)")
        print(" tickets: out/tickets/*.md  | report: docs/BENCHMARKS.md  | audit: out/audit.jsonl")
        ok = (result == "done" and tickets and resolved == len(tickets) and saf["out_of_scope_sent"] == 0
              and saf["audit_chain_ok"] and orch.false_positives == 0 and elapsed < 300)
        print(" DEMO " + ("PASSED" if ok else "FAILED"))
        code = 0 if ok else 1
        if args.keep_alive:
            say("ui", f"still serving http://127.0.0.1:{args.ui_port} ; Ctrl-C to stop")
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        for p in procs:
            p.terminate()
    return code


if __name__ == "__main__":
    raise SystemExit(main())
