# Preflight — Invariants (MVP: 8 property checks)

Each check asserts a business invariant on our own synthetic target, inside the scope allowlist, through
the safety gateway. Shape: run a normal flow (must pass), make one controlled variation, and assert the
safe behaviour. A deviation is a finding, confirmed only after the verifier reproduces it twice against a
clean control. The LLM proposes which invariant applies to which endpoint; these deterministic checks decide.

Review and reword these in your own voice — each member should be able to explain their checks.

## INV-01 · Refund never exceeds amount paid (business logic — money)
- Endpoint: `POST /api/v1/bookings/{booking_id}/refunds`
- Invariant: a refund amount is never greater than the booking's amount paid.
- Normal flow: book → pay → request a refund equal to (or below) the amount paid → succeeds.
- Variation: request a refund greater than the amount paid.
- Expected (safe): rejected (4xx), no refund recorded. A success is the finding.

## INV-02 · Tenant isolation on read (access control — cross-tenant)
- Endpoint: `GET /api/v1/bookings/{booking_id}`
- Invariant: a session can read only bookings belonging to its own tenant.
- Normal flow: as tenant A, read a booking owned by A → succeeds.
- Variation: as tenant A, request a booking id owned by tenant B.
- Expected (safe): denied (403/404), no tenant-B data in the response. Any leak is the finding.

## INV-03 · Role authority boundary (access control — privilege)
- Endpoint: an admin-only action, e.g. `POST /api/v1/admin/tenants/{tenant_id}/users`
- Invariant: only an admin role may call admin-only actions.
- Normal flow: as admin, perform the action → succeeds.
- Variation: repeat the identical request authenticated as a sub-agent.
- Expected (safe): denied (403), no state change. A success is the finding.

## INV-04 · Charged price equals server-quoted price (business logic — price integrity)
- Endpoint: `POST /api/v1/bookings/{booking_id}/pay`
- Invariant: the amount charged equals the price the server quoted for that offer; the client cannot set the price.
- Normal flow: hold → book → pay the quoted amount → succeeds at the quoted amount.
- Variation: submit the pay request with a client-supplied amount below the quote.
- Expected (safe): the server ignores the client amount or rejects; charge equals the quote. A charge at the lowered amount is the finding.

## INV-05 · No double refund (business logic — replay/idempotency)
- Endpoint: `POST /api/v1/bookings/{booking_id}/refunds`
- Invariant: a paid booking can be refunded at most once for its total.
- Normal flow: book → pay → refund once → succeeds.
- Variation: submit the same valid refund a second time.
- Expected (safe): the second is a no-op or rejected; total refunded never exceeds amount paid. A second payout is the finding.

## INV-06 · Valid state transitions only (business logic — skipped steps)
- Endpoint: `POST /api/v1/bookings/{booking_id}/pay` and `/refunds`
- Invariant: an action is allowed only from a valid prior state (can't pay an unbooked hold, can't refund an unpaid booking).
- Normal flow: follow the correct order hold → book → pay → (cancel) → refund.
- Variation: call refund on a booking that was never paid.
- Expected (safe): rejected (409/4xx), no money moved. A success is the finding.

## INV-07 · Ownership required to modify (access control — cross-agency write)
- Endpoint: `POST /api/v1/bookings/{booking_id}/cancel`
- Invariant: only the owning agency/agent may cancel or modify a booking.
- Normal flow: the owning agent cancels their own booking → succeeds.
- Variation: a different agency's agent calls cancel on that booking id.
- Expected (safe): denied (403), booking unchanged. A successful cancel is the finding.

## INV-08 · No sensitive-field exposure (data exposure)
- Endpoint: booking/invoice reads, and the shadow route `GET /internal/debug/config`
- Invariant: responses never return sensitive fields (full payment data, another traveller's PII) to a caller not entitled to them; internal/debug routes don't expose config or secrets.
- Normal flow: read an invoice as its owner → returns only the permitted fields.
- Variation: read the same resource as a lower-privilege role, and request the internal route.
- Expected (safe): sensitive fields absent; internal route denied or not present. Exposure is the finding.

Coverage: these 8 invariants map to the access-control, business-logic and data-exposure classes in the seed set
(~11 of the 20 seeded issues). The remaining classes (injection, session/auth, server-side) are out of MVP scope
and noted as future work in BENCHMARKS.md.
