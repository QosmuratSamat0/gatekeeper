# AUTH-04 — Account session management

Status: brief prepared by Codex; Gemini must present an implementation plan before coding.

## Goal and boundaries
Let an authenticated account see its active login sessions, revoke one of its
sessions, or sign out everywhere. Reuse AUTH-03 session families and revocation;
do not create another token system. No Access roles, Gateway, email delivery,
password recovery, device fingerprinting, Redis or cleanup worker in this slice.
Codex designs and reviews; Gemini writes implementation code.

## HTTP contracts
All endpoints require exactly one valid Bearer access JWT and a currently active
database session with an active account, as /me already does. A signature alone
must not authorize session management. Derive account ID and current session ID
from verified claims; never accept an account ID from the client.

- GET /v1/auth/sessions?limit=20&cursor=<opaque>
  - 200: {"sessions":[{"id":"uuid","created_at":"RFC3339 UTC",
    "expires_at":"RFC3339 UTC","current":true}],"next_cursor":null}.
  - Only own sessions with revoked_at IS NULL and expires_at > current time.
    Include legacy AUTH-02 sessions if still active. No token digests, raw tokens,
    password hashes, account IDs, IP addresses or invented device names.
  - Default limit 20, allowed 1..100; reject repeated/unknown query parameters,
    invalid integers and malformed cursors with 400 invalid_request.
  - Stable keyset order: created_at DESC, id DESC. Cursor encodes version,
    created_at and UUID with strict canonical base64url and bounded length.
    It is only a pagination position, never authorization; every query filters
    by the verified account ID. next_cursor exists only if another page exists.
  - Reject non-empty request bodies with 400 invalid_request.
- DELETE /v1/auth/sessions/{session_id}
  - UUID path parameter; no request body. Invalid UUID/body: 400 invalid_request.
  - 204 for an owned existing session, including already revoked/expired ones.
    Unknown ID and another account's ID both return 404 session_not_found.
  - Revoking the current session is allowed. Later /me, refresh and management
    requests using this family return 401.
- POST /v1/auth/logout-all
  - No request body; 204 only after revocation transaction commits.
  - Revoke all currently unrevoked sessions owned by this account, including the
    caller's session. Preserve session and consumed refresh records.
  - A later repeat with that revoked Bearer token returns 401; do not bypass
    authentication to claim endpoint idempotence.

Use Cache-Control: no-store on all management responses. Preserve existing
401 conventions, 413 for body overflow, 503 for classified DB timeout/unavailable,
500 for unexpected failures, request IDs and cancellation behavior. Body reading
must remain bounded to 4 KiB even when a body is forbidden. Do not log credentials
or arbitrary database errors. Existing login/refresh/logout contracts stay intact.

## Architecture and concurrency
- Keep cmd/api/main.go thin. Wire dependencies in internal/app/wiring.go.
- New usecases depend on narrow consumer-owned ports in internal/usecase;
  no imports of concrete PostgreSQL, token, or HTTP adapters.
- Repository methods accept context and verified account/current-session IDs.
  Ownership filters belong in the SQL as well as the usecase contract.
- Authenticate and recheck the caller's account/session under the relevant
  transaction locks before modifying state. Middleware checks alone can become
  stale while waiting for locks. Check actual time after lock acquisition.
- Single revocation follows account -> session locking and ownership checks;
  when caller and target differ, lock both session rows in ascending UUID order
  to prevent opposite-direction revocation deadlocks. Keep the account lock mode
  compatible with the logout-all rule below.
- Logout-all serializes with login and refresh: acquire the account row FOR UPDATE
  before session locks, then lock caller/session rows in ascending UUID order.
  Recheck active account and caller session under locks and revoke in one
  transaction. Existing login/refresh take account FOR SHARE first, so they
  cannot create/rotate a family midway through this operation.
- Login committed before logout-all acquires the account lock is revoked;
  login proceeding after logout-all commits may create a new session. This is
  snapshot logout-all, not a permanent account lock or password change.
- Refresh completing before revocation may return tokens, but its session is
  subsequently revoked; refresh after revocation returns 401. No usable surviving
  family from a pre-existing session after revocation commits.
- Preserve AUTH-03 account -> session -> refresh lock order and rollback rules.
  No cross-service SQL. Add a migration only if query/index evidence warrants it;
  never edit applied migrations. Propose the transaction design before coding.
- Local JWT-only validation by future business services still accepts issued
  access JWTs until expiry unless those services explicitly check revocation.
  Do not promise universal immediate logout. Auth endpoints check live sessions.

## Required verification
Unit/HTTP tests: Bearer missing/duplicate/expired, revoked caller, disabled account,
no-store, strict pagination, UUID/body errors, own/foreign/nonexistent session,
current marker and current-session revocation. Use generated temporary test keys,
never local keys or .env. Real PostgreSQL 16 tests in disposable databases:
1. Listing hides foreign, expired and revoked sessions; pagination has no
   duplicates when creation timestamps tie; empty page returns an empty array.
2. Target revoke is owner-scoped and idempotent, leaves another family usable.
3. Logout-all invalidates every existing family and caller, other accounts remain
   usable; a fresh login after commit works.
4. Concurrent refresh/single revoke, refresh/logout-all, login/logout-all and
   opposite-direction session revocation satisfy the defined outcomes without
   deadlock or partial commit. Synchronize tests with barriers/locks, not sleeps.
5. Revocation timeout/failure rolls back changes and does not return success.

Generate Swagger through the existing pinned Swag command; never edit generated
files manually. Run unit tests, go vet, gofmt, pinned golangci-lint v2.14.0,
Linux race tests, real PostgreSQL tests, Swagger regeneration diff check, Docker
build and configured Trivy check. Distinguish skipped checks from executed ones.
Add a short threat-model note for ownership isolation, stolen tokens, stale
middleware decisions and concurrent revocation. Explain new transaction policy
in an ADR and .ai/decisions.md; update architecture and README examples.

## Delivery
First present the proposed ports, DTOs, SQL/lock sequence, error mapping and test
plan for Codex review. No implementation until the plan is approved. Comments
must use simple English and explain why a check exists and what failure prevents.
Report each change's purpose, location and verification. Update current.md and
journal.md. Do not commit, push or deploy without a new user instruction.

## Later slices (not part of AUTH-04)
- AUTH-05: email verification, once delivery adapter and one-time-token policy
  are specified; do not silently require verified email for existing logins.
- AUTH-06: password recovery and atomic session revocation after password reset.
- Access/Gateway follow their separate architecture briefs.
