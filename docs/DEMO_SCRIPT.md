# Demo script (about 3 minutes on camera)

Run `make demo-live` (add `MANUAL=1` to click the approvals yourself). Open http://127.0.0.1:8001.

1. **The banner** (top): say it plainly. The invariants come from a *recorded replay of hand-authored
   fixtures*, not a live model. What you are showing is the pipeline around the model.
2. **Detect and map** (Timeline): "v1.0.0 deploy detected", 21 endpoints mapped with no spec. In the
   inventory: the v0 route is a *zombie*, the debug and webhook routes are *shadow*.
3. **Propose and confirm** (Invariants table): 8 proposals validated against the catalogue; INV-08 is
   low confidence and needs its own click. Nothing runs until a human confirms.
4. **Checks and approvals** (Needs a human): pay, cancel and refund are held. Each needs a named human.
   With the scripted operator you will see `demo-operator`; say that is a stand-in.
5. **A finding**: open FIND-INV-01. Show the normal flow (control) passing, then the violation twice on
   fresh bookings, the impact in rupees (labelled an assumption), the owner, the curl and the fix.
6. **Safety panel**: out-of-scope requests sent = 0, audit chain valid. Optionally press the kill
   switch to show the run pause (state PAUSED_SAFETY).
7. **The fix**: "v1.1.0 deployed". The orchestrator re-runs each stored reproduction. Tickets flip to
   Resolved. The scoreboard shows 0 false positives on the fixed build.
8. **Be upfront**: 6 of 20 seeded issues, not blind, crAPI/VAmPI not run (see BENCHMARKS.md).
