# ADR 0007: Account Session Management and Concurrency Design

## Status
Accepted

## Context
Step AUTH-04 extends the Gatekeeper authentication service with account session management capabilities:
1. `GET /v1/auth/sessions?limit=20&cursor=...`: Keyset-paginated listing of active sessions owned by the authenticated caller.
2. `DELETE /v1/auth/sessions/{session_id}`: Targeted revocation of a specific session owned by the authenticated caller.
3. `POST /v1/auth/logout-all`: Atomic revocation of all active sessions belonging to the authenticated account.

Key security and concurrency requirements:
- **Ownership Verification Before Locking**: Target sessions must be scoped by `account_id = verifiedAccountID` in the locking query (`FOR UPDATE`). Foreign sessions belonging to other accounts must never be locked; both nonexistent and foreign sessions return `404 session_not_found`.
- **Distinct Caller vs Target Errors**: A caller whose access token claims a session that no longer exists in PostgreSQL, has expired, or has been revoked must receive `401 unauthorized` (`ErrCallerSessionNotFound`). `404 session_not_found` (`ErrSessionNotFound`) is strictly reserved for target sessions in revocation requests.
- **Deadlock-Free Concurrent Revocations**: In mutual revocation races (e.g. Session A revokes Session B while Session B revokes Session A), rows must be locked in a globally consistent order (deterministic ascending UUID order: `id IN ($2, $3) ORDER BY id ASC FOR UPDATE`). The winning transaction acquires both locks and revokes the target; the losing transaction observes its caller session revoked after acquiring locks and returns `401 unauthorized` with zero deadlocks.
- **Fresh Wall-Clock Expiry**: PostgreSQL transaction `NOW()` is fixed at transaction start and can become stale during lock acquisition waits. Expiry must be evaluated using `clock_timestamp()` or fresh wall-clock time after acquiring locks.
- **Single-Statement Atomic Listing**: The listing query must verify the caller's active session, check account active status, evaluate expiry with a single statement timestamp, and fetch page items without window anomalies or race conditions.
- **Opaque Tamper-Proof Cursor**: Keyset pagination cursors must be opaque, strictly validated, and reject invalid versions, invalid UUIDs, trailing data, or nanosecond timestamps that lose precision when converted to PostgreSQL microseconds.

## Decision
1. **Database Schema & Indexing (`000004_sessions_keyset_index`)**:
   - Create composite partial index:
     `CREATE INDEX idx_sessions_account_active_keyset ON sessions (account_id, created_at DESC, id DESC) WHERE revoked_at IS NULL;`
   - Covers active session keyset lookups efficiently without table scans.

2. **Keyset Cursor Specification**:
   - Cursor payload format: `{"v":1,"c":"2026-10-07T12:00:00.123456Z","i":"<uuid>"}` encoded in canonical unpadded Base64URL.
   - Enforce trailing byte rejection using a secondary `json.Decoder.Decode` requiring `io.EOF`.
   - Reject timestamp precision exceeding PostgreSQL microsecond precision (`t.Truncate(time.Microsecond).Equal(t)`).
   - Validate UUID structure using standard hex parsing without external libraries.

3. **Live Single-Statement Listing**:
   - Execute in a single query with CTEs: `now_t` (`clock_timestamp()`), `caller` (verifies account active, caller session active, unrevoked, unexpired), and `page` (fetches up to `limit + 1` rows matching keyset tuple `(created_at, id) < (cursor_created_at, cursor_id)`).
   - Use `EXISTS (SELECT 1 FROM caller)` to determine caller presence (evaluating to strict boolean `false` if caller is absent, preventing NULL return from scalar subqueries).
   - Enforce `ORDER BY p.created_at DESC NULLS LAST, p.id DESC NULLS LAST` on the outer query to guarantee deterministic result ordering.
   - Strip sensitive tokens (`refresh_tokens` or credentials); return only public metadata: `id`, `created_at`, `expires_at`, `user_agent`, `ip_address`, `is_current`.

4. **Targeted Revocation (`DELETE /v1/auth/sessions/{session_id}`)**:
   - Lock caller and target session rows in ascending UUID order with `WHERE account_id = $1 AND id IN ($2, $3)`.
   - If caller row is missing or revoked/expired, return `401 unauthorized`.
   - If target row does not exist for the account, return `404 session_not_found`.
   - Idempotency: if target is already revoked or expired, return `204 No Content` without updating.
   - Revoke with `UPDATE sessions SET revoked_at = clock_timestamp()`.

5. **Logout-All (`POST /v1/auth/logout-all`)**:
   - Serialize with `accounts (FOR UPDATE)` to eliminate concurrency races with login and refresh token issuance.
   - Lock all unrevoked sessions of the account in ascending UUID order (`ORDER BY id ASC FOR UPDATE`).
   - Re-verify caller session state from the locked rows; if caller is missing/revoked/expired, return `401 unauthorized`.
   - Atomically revoke all active sessions: `UPDATE sessions SET revoked_at = clock_timestamp() WHERE account_id = $1 AND revoked_at IS NULL`.

6. **HTTP Boundaries & Caching**:
   - Apply `Cache-Control: no-store` to all authenticated session endpoints.
   - Enforce strict empty body policy: return `413 payload_too_large` if body exceeds 4 KiB, or `400 invalid_request` if non-empty body is provided for GET, DELETE, or POST logout-all.

## Consequences
- (+) Leak-free, ownership-filtered session management endpoints.
- (+) Provably deadlock-free concurrent revocations via deterministic ascending UUID lock sorting.
- (+) Atomic, race-free session listing with live caller verification in a single database round-trip.
- (+) Strict opaque keyset cursor prevents tamper attacks and paging inconsistencies.
- (-) Keyset pagination requires client to iterate sequentially using cursors; offset jumps are intentionally not supported.
