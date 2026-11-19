# Architecture

See the diagrams in the README. Components and where they live:

| Component | Module | Status |
|---|---|---|
| Target app (2 tenants, 3 roles, vulnerable/fixed deploys) | `target/` | done |
| Ground truth (20 issues, 9 classes) | `seeds/` (defender-only) | done |
| Safety gateway, approvals, kill switch, audit | `preflight/safety/` | done |
| Change watcher | `preflight/orchestrator/watcher.py` | done: version + bundle hash |
| Recon + inventory + OpenAPI | `preflight/recon/`, `preflight/inventory/` | done: bundle (regex), HAR, logs |
| Invariant proposal + validation + rulebook | `preflight/discovery/`, `preflight/llm/` | done: recorded replay |
| Planner (one plan per confirmed invariant) | `preflight/planning/` | done |
| Flow replay, 8 property checks, verifier | `preflight/execution/` | done |
| Triage, tickets, retest | `preflight/triage/`, `preflight/reporting/` | done |
| Orchestrator state machine | `preflight/orchestrator/machine.py` | done |
| Control room | `preflight/ui/` | done (minimal) |
| Demo runner, benchmark scorer | `demo/`, `bench/` | done |

## Data flow

`ApiMap` (recon) -> LLM proposes `InvariantCandidate`s -> validated against `CATALOGUE` and the map ->
`Rulebook` (human confirms) -> `CheckPlan`s -> `Flow` replays the recorded journey to the needed state ->
a check runs the normal flow + one variation via `ApiClient` -> `verify()` needs 2 violations and a
passing control -> `triage()` -> `TicketStore` -> after the next deploy `retest_ticket()`.

## Target app

`POST /_deploy` (header `X-Deploy-Token`) switches the build: `{"version", "mode": "vulnerable" |
"fixed", "patched": ["S01"], "reset": false}`. `GET /_version` returns only the version, never the mode.

## Config over code

Scope, limits and reserved actions (`preflight/safety/*.yaml`), severity and owners
(`preflight/triage/*.yaml`), sensitive-field rules (`preflight/execution/sensitive_fields.yaml`),
fixes (`preflight/reporting/fixes.yaml`), LLM routing (`preflight/llm/llm.yaml`).

Owners: _(fill in per module before the finals: each member must be able to explain theirs)_
