# ADR 0006: Rotating Refresh Tokens, Reuse Detection, and Session Family Revocation

## Status
Accepted

## Context
Step AUTH-03 extends the Gatekeeper authentication service with long-lived session continuity for API and mobile clients using rotating refresh tokens.

Key architectural and security considerations:
1. **Client Transport Decision**:
   - Primary clients are native mobile apps and API clients communicating over JSON.
   - Refresh tokens are transmitted in request/response JSON bodies, stored securely in OS-protected credential stores (iOS Keychain / Android Keystore).
   - Browser cookies and CSRF protections are deferred to a separate subsequent design slice.
2. **Token Format and Storage**:
   - Refresh tokens are opaque, 32 cryptographically random bytes generated via `crypto/rand` and encoded in canonical unpadded Base64URL (strictly 43 ASCII characters).
   - Only the SHA-256 digest (`BYTEA`, strictly 32 bytes) is stored in the database. Raw refresh tokens are never persisted, logged, or retained in database tables.
   - Fast hashing (SHA-256) is appropriate because the tokens possess 256 bits of high-entropy cryptographic randomness (unlike passwords which use Argon2id).
3. **Session Families and Reuse Detection**:
   - One login session represents one refresh family. The session record (`sessions.id`) is the root of the family.
   - All rotated access JWTs retain the stable `sub` and `sid`.
   - `REFRESH_SESSION_TTL` defines the absolute lifetime of the family (default 720h / 30 days, accepted 24h–720h). Rotation never extends this absolute boundary.
   - Consumed tokens (`consumed_at IS NOT NULL`) are retained until family expiration. If an already consumed token is presented again (replay), the entire family is revoked immediately by updating `sessions.revoked_at` and committing the revocation before returning generic 401.
4. **Transaction Boundaries & Lock Order**:
   - To prevent deadlocks, a strict row lock acquisition order is established across all operations:
     `accounts (FOR SHARE)` -> `sessions (FOR UPDATE)` -> `refresh_tokens (FOR UPDATE)`.
   - State is re-verified after acquiring locks using actual wall-clock time (`now = clock_timestamp()`): account status, session revocation, session expiration, token expiration, and consumption status.
   - If after integer-second truncation/rounding of the JWT expiration `exp <= iat`, the operation aborts and returns generic 401 without consuming the token.
5. **Separation of Concerns**:
   - Raw refresh tokens are generated in the use case layer; the repository receives only the successor token's SHA-256 hash and signs the access token via a callback that receives the locked session's expiration timestamp. The repository returns the signed access token and exact expirations, and the use case attaches the raw refresh token upon successful commit.
6. **Dual-Mode Logout**:
   - `POST /v1/auth/logout` supports two mutually exclusive modes:
     - Bearer mode: `Authorization: Bearer <access_jwt>`, empty body. Validates access token and verifies ownership (`session.account_id == account_id`).
     - Refresh mode: No `Authorization` header, JSON body `{"refresh_token": "..."}`. Works even after the access token has expired.
   - Providing both modes simultaneously is rejected with `400 invalid_request`.

## Decision
1. **Database Schema (`000003_create_refresh_tokens`)**:
   - Add table `refresh_tokens` referencing `sessions(id)` with `ON DELETE CASCADE`.
   - `token_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32)`.
   - `CONSTRAINT chk_refresh_tokens_expiry_order CHECK (expires_at > created_at)`.
   - `CONSTRAINT chk_refresh_tokens_consumed_order CHECK (consumed_at IS NULL OR consumed_at >= created_at)`.
   - `CREATE UNIQUE INDEX uq_refresh_tokens_active_session ON refresh_tokens (session_id) WHERE consumed_at IS NULL`.
2. **Access Token Clamping**:
   - Access token default lifetime is 10 minutes (`config.AccessTokenTTL`), clamped to `session.expires_at`.
3. **Rate Limiting**:
   - Independent instances of the bounded-map `IPRateLimiter` applied to `/v1/auth/refresh` and `/v1/auth/logout` (10 req/min per `RemoteAddr` IP, capacity 10,000, fail-closed on capacity overflow).

## Consequences
- (+) Secure, long-lived sessions with automatic credential rotation.
- (+) Immediate detection of token theft via replay of consumed tokens, revoking compromised sessions.
- (+) Deterministic concurrency handling and deadlock prevention via unified lock order.
- (+) Support for logging out after access token expiry via refresh-authenticated logout.
- (-) Clients must serialize refresh requests to avoid accidental self-invalidation due to strict replay detection.
