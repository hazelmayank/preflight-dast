# Architecture

See the flowchart in the README. Phase 0 delivers the safety layer and the synthetic target.

| Component | Module | Status |
|---|---|---|
| C1 Target app | `target/` | done: 2 tenants, 3 roles, search > hold > book > pay > cancel > refund, invoices, PII, supplier webhook, vulnerable/fixed deploys |
| C2 Seed harness | `seeds/` (defender-only) | done: 20 seeds, 9 classes |
| C8 Safety gateway | `preflight/safety/` | done |
| C3 Change watcher | `preflight/orchestrator/` | Phase 1 |
| C4-C5 Recon, inventory | `preflight/recon/`, `inventory/` | Phase 2 |
| C6-C7, C9 Rules, planner, verifier | `discovery/`, `planning/`, `execution/` | Phase 3 |
| C10-C13 Triage, report, UI, benchmark | `triage/`, `reporting/`, `ui/`, `bench/` | Phase 4 |

## Target app

`POST /_deploy` (header `X-Deploy-Token`) switches the build: `{"version", "mode": "vulnerable" |
"fixed", "patched": ["S01"], "reset": false}`. `GET /_version` returns only the version, never the
mode. `make data` writes 30/90-day access logs and a HAR to `target/data/` (zombie `/api/v0`, shadow
`/internal/debug/config` and webhook traffic included).

Owners: _(fill in per module)_
