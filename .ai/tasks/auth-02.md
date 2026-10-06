# AUTH-02: login, access JWT, sessions and logout

Date: 2026-10-05. Implementation brief for Gemini; Codex architects and reviews.
AUTH-01 registration review is closed for the previously reported findings.
No commit, push, deployment or editing/reading local .env files.

## Outcome and boundaries
User can register, log in, call a protected account endpoint, and log out.
Login issues a short-lived access JWT and persists a session. This slice issues
NO refresh token. After expiry the user logs in again; refresh rotation is AUTH-03.
No Access/roles, Gateway, MFA, recovery, email verification, OAuth/OIDC claims,
Redis, events or infrastructure expansion. Accounts with email_verified=false
may log in in this initial contract; disabled accounts may not.

## Architecture
Keep cmd/api thin and compose all dependencies in app/wiring.go.
- domain: Session and typed outcome errors.
- usecase: login.go, current_account.go, logout.go, consumer-owned ports.
- delivery/http: login/me/logout DTOs and handlers, shared HTTP error mapping;
  middleware for bearer token verification and login request limiting.
- repository/postgres: account lookup, sessions, transactional login persistence.
- platform/password: extend current Argon2id adapter with Verify.
- platform/token: vetted JWT library, signing and verification, public JWKS.
- app: lifecycle, config injection and assembly only.
HTTP must not import PostgreSQL adapters. Only app assembles concrete types.
Domain/usecases must not import HTTP, JWT or SQL libraries.

## Actions for Gemini, with purpose
1. Read instructions, inspect AUTH-01 and present a bounded plan.
   Why: preserve registration, health endpoints, Swag and existing local tooling.
2. Write a dependency/key-policy ADR; select and pin a maintained JWT library
   (proposed github.com/golang-jwt/jwt/v5) before adding it.
   Why: signature verification should use vetted code and explicit algorithms.
3. Extend password adapter with strict PHC parsing and Verify(ctx,password,hash).
   Why: compare the submitted password to the stored hash without storing plaintext.
4. Add the sessions migration and account/session repository operations.
   Why: login state must survive restarts and support logout across replicas.
5. Add token signing, strict verification and JWKS projection.
   Why: future services can verify identities using public keys, without signing secrets.
6. Implement login, current-account and logout usecases, then HTTP adapters.
   Why: business operations remain testable independently of HTTP and PostgreSQL.
7. Add bearer middleware and bounded local login rate limiting.
   Why: protected handlers require verified credentials; password checks are costly.
8. Generate Swag contracts, update README and .env.example only.
   Why: users can test the actual API; never read or edit a real .env.
9. Execute acceptance checks and report evidence for Codex review.
   Why: passing compilation alone does not prove token security or session revocation.
Explain each action before doing it and its verified result afterward. Code comments
use plain English to explain reasons, limits and failure behavior, not repeat syntax.

## HTTP contracts
All errors retain AUTH-01's error envelope with request_id. Token/user responses
include Cache-Control: no-store. JSON input is strict, at most 4 KiB, unknown fields
and trailing values rejected. Preserve 400/413/415 behavior from registration.

POST /v1/auth/login (public):
Request: {"email":"user@example.com","password":"example-password"}
200: {"access_token":"<JWT>","token_type":"Bearer","expires_in":600,
      "account":{"id":"<uuid>","email":"user@example.com",
                 "status":"active","email_verified":false}}
No refresh token, roles or password/hash fields.
401 invalid_credentials: identical status/message for unknown email, wrong password
and disabled account. 429 rate_limited with Retry-After, 503 service_unavailable
for known availability/timeouts; unexpected errors -> 500 internal_error.
Malformed input -> 400. Email policy matches registration; do not lowercase/trim
passwords. Login bounds: nonempty valid UTF-8, maximum 128 code points/512 bytes;
short passwords must receive generic 401, not disclose account-specific rules.

GET /v1/auth/me (protected):
200: {"account":{"id":"<uuid>","email":"user@example.com",
                 "status":"active","email_verified":false}}
Validate JWT, persisted session ownership/expiry/revocation and current account
status. Invalid credentials or session/account state -> generic 401 unauthorized.
Do not accept user ID from headers, query or body.

POST /v1/auth/logout (protected, no request body):
Verify access JWT, revoke only the session identified by its sid and sub.
204, no response body. Repeating logout with the same unexpired JWT returns 204
if that session is already revoked; unknown/mismatched session -> 401.
Do not use middleware that rejects revoked sessions before this idempotent operation.
Invalid/expired JWT -> 401. Database failures follow 503/500 mapping.

GET /.well-known/jwks.json (public):
200 standard {"keys":[...]} with public signing keys only. Cache-Control:
public, max-age=60. No private fields. No request-supplied jwks URL is followed.

## JWT and key policy
Use Ed25519 / JWT alg EdDSA, key ID kid, typ JWT. Claims: sub=account UUID,
sid=session UUID, iss, aud (configured exact audience), iat, exp, jti=random UUID.
Default lifetime 10 minutes, configurable 1-15 minutes. No PII, passwords or roles.
Verifier enforces alg, key ID, issuer, audience, required claim presence/types,
UUID IDs, expiry and sensible issued-at time; allow at most 30s clock skew.
Reject alg none, algorithm substitution, missing/unknown kid, malformed claims,
wrong issuer/audience and expired tokens. Do not trust jku/x5u or embedded caller keys.
Bearer scheme is case-insensitive; reject missing/empty/multiple token credentials.

Signing key is an externally supplied Ed25519 PKCS#8 PEM; verify key type at startup.
No generated ephemeral startup key, committed key or private key in example files.
Env config: JWT_ISSUER, JWT_AUDIENCE, JWT_ACTIVE_KID, JWT_PRIVATE_KEY_FILE,
ACCESS_TOKEN_TTL=10m. Key file is runtime secret material; Gemini must not read any
developer key. Tests generate their own keys in memory/disposable locations.
Document a developer key-generation command without executing it for the user.
For initial rotation, configure an optional public-key set file of old JWKS keys;
publish active + previous public keys, enforce unique kids and Ed25519 key type.
Retain previous keys at least old-token lifetime + skew + JWKS cache duration.
Restart replicas with a coordinated shared key set; no hot-reload mechanism here.
Startup errors report safe categories without paths/content containing secrets.

## Password verification and login behavior
Parse PHC format strictly, bound supported Argon2id parameters before allocating
memory, require expected version and safe salt/hash lengths. Reject malformed hashes
as an internal credential-storage failure. Never log hashes. Hash and Verify share
the SAME concurrency limiter; no separate pools bypassing the memory budget.
Use subtle.ConstantTimeCompare on computed vs stored bytes.
For missing accounts verify against a dummy hash with current production parameters;
do password verification for disabled accounts before generic denial as well.
Generate dummy hash once at startup, not per request. This reduces obvious timing
differences; do not claim constant total login latency. Test dummy verification calls.

## Storage and atomicity
Add a NEW migration 000002_sessions; do not edit 000001.
sessions: id UUID PK; account_id UUID NOT NULL FK accounts(id);
created_at TIMESTAMPTZ NOT NULL; expires_at TIMESTAMPTZ NOT NULL;
revoked_at TIMESTAMPTZ NULL; index account_id; expiry after creation.
Session expiry equals the access JWT expiry for this slice. No stored access JWT.
Repository consumer port supports session creation with an atomic active-account
check, session/account lookup and idempotent revoke constrained by account ID.
Sign JWT before inserting the session; do not send it unless insertion commits.
Check active account AND unchanged credential hash atomically during insertion
to avoid issuing sessions after concurrent disable/credential changes. PostgreSQL
transaction/row locking belongs in adapter, not usecase. Explicitly test this behavior.

## Login limits and logs
Per-replica bounded limiter for POST login: initial 10 attempts/minute per source
IP, applied before hashing, finite entry capacity/TTL cleanup and no goroutine per
request. Use remote peer address; do not trust client X-Forwarded-For. Configurable
positive limits. No account lockout attackers can use to disable other users.
Local limiter is not distributed; document that replicas require shared controls
before public deployment. Do not add Redis in this task.
Log safe event categories/request IDs; never log bodies, credentials, JWTs, hashes,
Authorization, private keys or arbitrary adapter error text.

## Acceptance evidence
- Registration still accepts 8, rejects 7 code points; existing tests pass.
- Login verifies correct passwords; wrong/missing/disabled cases yield same 401
  and dummy verification executes for missing users. Malformed PHC cannot force
  unbounded allocation; Hash and Verify combined concurrency is bounded.
- JWT verifies with published key; negative alg/kid/claim/time/key cases are tested.
  JWKS has no private fields; old/new keys behave according to documented rotation.
- Real PostgreSQL tests: login creates session, /me succeeds, logout returns 204,
  /me then returns 401, repeat logout 204, expiry/disabled account denied; session
  cannot be revoked by another account; concurrent account-disable check is atomic.
- Rate limit returns 429 before hashing; spoofed forwarding header does not evade it.
- Known DB failures -> 503; unexpected -> 500, without leaked secrets in logs/responses.
- Tests use isolated disposable DB and opt-in; run actual integration and Linux
  -race, go build, vet, lint, Docker build and generated Swag drift check.
- Report executed vs skipped checks separately. Do not claim a raw signature check
  provides immediate revocation: Auth checks sessions for /me; future services doing
  local JWT verification may accept logged-out tokens until expiry (plus clock skew).

## Handoff
Gemini presents a plan and implementation ADR(s) per workflow, then implements
only AUTH-02 and returns it for Codex review. User controls delivery. A browser
refresh-cookie/CSRF design and rotating refresh tokens are reserved for AUTH-03;
do not add a partially usable refresh token now. Swagger enable flag remains a
separate recorded follow-up, not a reason to expand this implementation.
