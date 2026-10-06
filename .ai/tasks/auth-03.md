# AUTH-03 - Rotating refresh tokens

Status: implementation brief prepared by Codex, 2026-10-06. AUTH-02 review is closed.
Gemini writes implementation code; Codex reviews its plan and result.
Next: Gemini presents its plan for Codex review before implementation.
No commit, push or deploy is authorized by this brief.

## Approved client transport

User decision: API/mobile clients with refresh tokens in JSON. No authentication
cookies, browser refresh flow or new CORS configuration in this slice. Clients
use OS-protected credential storage (Keychain/Keystore or equivalent) and HTTPS
outside loopback development. This is not a recommendation to use localStorage
for browser tokens. A browser cookie/CSRF design is a separate future task.

## Scope and architecture

Extend Auth with refresh issuance on login, POST /v1/auth/refresh, atomic rotation,
reuse detection and revocation of the associated login session. No roles,
Access/Gateway implementation, OAuth/OIDC claims, Redis, MFA or recovery flows.
Keep main thin, composition in app/wiring.go, consumer-owned ports in usecase,
HTTP DTOs in delivery, transaction and row locking in repository/postgres.
Use plain English comments explaining why security decisions exist.

## Session and token model

One successful login creates one session; that session is the refresh family.
All refreshed access JWTs keep its sid and sub, with new jti, iat and exp.
Access lifetime remains the AUTH-02 policy. Session expiry now means absolute
login lifetime, not access JWT expiry. REFRESH_SESSION_TTL defaults to 720h;
accept duration values from 24h to 720h. Rotation never extends the family's
absolute lifetime. Clamp issued
access expiry to session expiry so /me does not reject a newly issued token early.
Old AUTH-02 sessions retain their existing expiry and do not gain refresh tokens.

Refresh token: 32 cryptographically random bytes, canonical unpadded base64url;
opaque, not JWT. Store only SHA-256 digest (BYTEA, 32 bytes, UNIQUE), never raw
tokens. A fast hash is appropriate because these tokens have 256 random bits;
passwords continue to use Argon2id. No tokens in URLs, logs or DB columns.

Add a new migration, never modify applied 000001/000002. Refresh records need
id, session_id FK, token_hash, created_at, expires_at and consumed_at. Preserve
consumed digests until family expiry so replay remains detectable. Enforce
one unconsumed token per family through a partial unique index. Revocation lives
on sessions.revoked_at; no second competing family revocation state.

## Atomic operations

Login: generate and sign credentials before commit; insert session and initial
refresh digest in one transaction with the existing active-account/unchanged-hash
check. Return credentials only after successful commit.

Refresh: validate encoding/length, hash token, derive identity from the stored
record, not caller IDs. The repository owns a bounded transaction. Serialize
operations for the same family with a session row lock and re-read refresh state
after taking the lock. Enforce one consistent lock order across login, refresh,
logout and account checks; Gemini's plan must explain it.

For active account/session and an unconsumed unexpired token: sign the successor
access JWT, mark presented refresh consumed and insert one successor digest.
The new token expiry is the family's absolute expiry. Commit all changes before
returning credentials. Generation/signing/DB failure must not consume a token
without creating its successor. Signing is a consumer port; no SQL in usecase
and no concrete signing adapter dependency in the repository.

If a consumed token from an active family is presented again: revoke that family
and COMMIT the revocation before returning generic 401. Returning a domain error
must not accidentally roll back this security update. Unknown, expired, revoked
or disabled credentials receive generic 401; unknown tokens cannot revoke an
arbitrary family. Revocation of one login does not revoke other logins.

Concurrent requests using the same refresh: at most one rotation succeeds;
the subsequent replay revokes the family, including the successor. Strict policy:
no grace window, no replay of cached raw tokens. A response lost after commit can
force re-login on retry. Document this and require clients to serialize refresh
requests; do not silently retry an uncertain successful refresh.

Logout must atomically revoke the family, block further refresh and preserve
idempotent 204 for valid repeated logout, including refresh-authenticated logout
after access expiry. Auth /me
checks persisted revocation; other services verifying JWTs locally can continue
accepting old access JWTs until expiry plus permitted skew.

## HTTP and operational requirements

POST /v1/auth/login: retain existing request and account response. Successful
200 adds refresh_token and refresh_expires_in (integer seconds remaining until
absolute session expiry) alongside access_token, token_type="Bearer", expires_in
and account. Registration remains registration-only; no automatic token issuance.

POST /v1/auth/refresh: application/json body {"refresh_token":"<opaque token>"}.
No access JWT required; do not apply Bearer middleware or interpret an optional
Authorization header as identity here. 200 JSON: access_token, token_type,
expires_in, refresh_token, refresh_expires_in. No account field or caller IDs.
Every success returns a new refresh; the old token is consumed. Missing, null,
non-string or empty refresh field is 400 invalid_request; incorrect token encoding
or unknown/expired/revoked/replayed token is generic 401 invalid_credentials.
Require exactly 43 ASCII base64url characters decoding to exactly 32 bytes and
round-trip canonical encoding; reject padding, whitespace and alternative encodings.

POST /v1/auth/logout supports exactly one credential mode:
- Existing mode: one Authorization Bearer access JWT, empty body, no Content-Type
  required. Keep AUTH-02 signature/expiry validation and idempotent 204 behavior.
- Refresh mode: no Authorization header, application/json body containing only
  refresh_token. Locate family from its digest, lock and revoke atomically. A known
  unexpired token from that family, even consumed or already revoked, permits
  idempotent 204. Unknown/expired/malformed token is generic 401. This operation
  never rotates credentials. It works without a valid access JWT.
Reject combined header/body credentials with 400 invalid_request; do not fall
back to refresh if Bearer verification fails. Reject multiple Authorization
headers. No credentials is 401. Never accept session/account IDs from the caller.
Routes cannot place both logout modes behind unconditional Bearer middleware.

All JSON bodies are limited to 4 KiB, must be exactly one non-null object and
reject unknown fields and trailing values. Oversized bodies (including tails)
are 413; invalid Content-Type is 415; malformed requests are 400. Preserve generic
401, 429 with Retry-After, 503 for timeout/known DB unavailability and 500 for
unexpected failures. On client cancellation do not write a response.
Use the existing error envelope. Do not disclose whether replay caused revocation.
Use no-store for credential/account responses and logout responses. Strict input,
bounded bodies, generic auth errors, safe request IDs, cancellation and 503/500
mapping remain required. Bound refresh attempts per peer IP before DB work;
reuse the approved bounded per-replica limiter pattern and document its limits.
Use separate bounded limiter instances for refresh and logout (initial 10/min/IP)
so attempts do not consume the login budget. Use RemoteAddr, not forwarding headers.
Mobile clients must serialize refresh calls across their concurrent API requests
and atomically replace their stored refresh after success; clear credentials on 401.
Do not implement client code in this backend task.

## Acceptance and handoff

Gemini first presents the storage migration, transaction boundary/ports, lock
order, final HTTP contracts, threat model and tests. Codex reviews the plan.
Record the approved design in a new ADR; generate Swagger from annotations.

Tests must cover real PostgreSQL login/initial refresh atomicity, successful
rotation with exact expiries and stable sid, replay revocation that persists,
concurrent same-token refresh, refresh-versus-logout races, disabled accounts,
expiry, isolated families, signing/transaction failure rollback and generic errors.
Include exact JSON DTOs, strict decoding, no-store, both logout modes after access
expiry, ambiguous credentials, rate limits and cancellation/timeout HTTP tests.
Do not label sequential status updates as a concurrency test.

Run unit tests, isolated PostgreSQL 16 integration tests, Linux race detector,
go build, go vet, pinned CI golangci-lint, gofmt, Docker build and Swag drift check.
Provide command, exit code and output; distinguish skipped checks. Integration
tests must opt in and never use the developer's DB. Never inspect local .env or
developer key files. No commit/push/deploy without separate user instruction.
