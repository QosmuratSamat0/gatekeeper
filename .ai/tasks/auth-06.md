# AUTH-06 — Password recovery by email

Status: prepared by Codex on 2026-10-10. Design is proposed in ADR 0009 and
must be reviewed by Gemini in a written implementation plan before coding.
No implementation, commit, push or deployment is authorized by this task.

## Goal

Let an account owner who can access their registered email set a new password
without knowing the old one. Keep the account, email-verification state, and
existing API contracts intact except for the two recovery endpoints.

## Proposed boundaries

In scope:
- Public request and confirmation endpoints for password recovery.
- One-time opaque tokens delivered through the existing `EmailSender` port.
- In-process bounded email delivery dispatcher (channel + worker pool) decoupling remote SMTP latency from HTTP responses.
- Digest-only PostgreSQL persistence, expiry, replacement, and one-time use.
- Argon2id password hashing using the existing bounded hasher.
- Atomic password update and revocation of every active session for the account.
- Rate limits, threat-model note, generated Swagger, README and tracked config template.

Out of scope: changing email addresses, verifying an email as a side effect,
login policy changes, MFA, roles, Access/Gateway, external mail vendors, external
distributed message brokers (Kafka, RabbitMQ, Redis), persistent outbox table,
HTML email, and frontend/deep-link work.

## HTTP contract

`POST /v1/auth/password-reset/request` is public and accepts
`{"email":"user@example.com"}`. Validate its JSON using existing strict
decoder conventions. For every syntactically valid email, return the same
`202 Accepted` response, whether or not an eligible account exists. Send mail
only for an existing active account with a verified email. Do not disclose
account existence through response status, body, or error message. Apply the
existing bounded per-IP limiter and a database-backed per-account cooldown
(proposed default: 60 seconds). If SMTP delivery fails, keep the public
response generic and log only a safe failure category and request ID; do not
log the address, token, message, SMTP response text, or credentials.

`POST /v1/auth/password-reset/confirm` is public and accepts
`{"token":"<opaque token>","new_password":"<new password>"}`. Apply
strict decoding, body limits, password length rules already used by
registration (minimum 8 characters), and bounded per-IP rate limiting.
Return `204 No Content` only when the token is valid and the password has been
changed. All invalid, unknown, expired, superseded, consumed, or malformed
tokens return the same generic `400 invalid_password_reset_token` response.
Responses containing token/account state use `Cache-Control: no-store`.

## Token, storage, and transaction policy

- Generate 32 random bytes with `crypto/rand`, encoded as canonical unpadded
  base64url. Store only a SHA-256 digest; never persist or log the raw token.
- Proposed token lifetime is 30 minutes. Allow only one current token per
  account; issuing a replacement invalidates the previous token.
- Store reset tokens in a new bounded table with account FK, unique 32-byte
  digest, expiry and issuance/cooldown data. Add a new migration; never edit
  applied migrations. Check the repository's current migration number before
  naming it.
- Use a database-backed 60-second per-account cooldown so replicas cannot
  bypass it. Return the same generic 202 while a request is suppressed.
- Confirmation is one transaction: lock account first, then reset token,
  recheck token and expiry after locks, update the Argon2id password hash,
  consume the token, and revoke every active session. Follow the existing
  canonical lock ordering used by refresh and session management; document
  the complete order before implementation to avoid deadlocks.
- If any write fails, roll back the whole transaction. Concurrent confirms
  must produce exactly one success. A successful reset leaves account status
  and `email_verified` unchanged. Existing access tokens must stop working
  through the normal revoked-session check; refresh tokens must no longer work.
- Do not hold a database transaction or row locks during SMTP I/O. Persist
  the token before sending and dispatch delivery via an in-process bounded dispatcher
  (8 slots, 4 workers) using a dedicated application worker context. Remote SMTP I/O
  is excluded from the HTTP response path, allowing immediate generic 202 responses.
  Note that while the queue removes macroscopic SMTP latency, it does not guarantee
  eliminating timing differences between existing and unknown accounts due to database
  operations (residual timing side-channel remains in the threat model).
- On queue overflow, tasks are dropped without blocking; the server logs a safe failure
  category and continues returning generic 202. The user can retry after the 60s cooldown,
  provided load has normalized. On ungraceful process crashes, in-flight queued tasks may
  be lost before transmission; recovery is likewise achieved via retry after cooldown.
- On graceful shutdown, drain waits up to 45 seconds for active and queued tasks to complete
  before closing the database connection pool. Deployment manifests must set
  `terminationGracePeriodSeconds` to at least 75 seconds (accounting for 10s HTTP shutdown,
  45s queue drain, and safety margin) to avoid premature SIGKILL.

## Architecture and plan required before coding

Keep `cmd/api/main.go` thin. Define consumer-owned ports in `internal/usecase`,
put SQL in `internal/repository/postgres`, HTTP DTOs/handlers in
`internal/delivery/http`, and reuse the injected email and password-hashing
adapters. No new dependency without a separate ADR and user approval.

Before coding, Gemini must submit a short plan for Codex review covering:
1. Use cases, ports and adapter wiring.
2. Endpoint DTOs, status/error behavior and generated Swagger annotations.
3. Token schema, cooldown, lock order and atomic session/refresh revocation.
4. Generic response behavior, rate limits and SMTP failure/retry behavior.
5. Unit, HTTP and PostgreSQL concurrency tests plus threat-model coverage.

## Required verification

- Token format, randomness and digest-only persistence tests.
- Request endpoint gives identical public response for existing, unknown,
  unverified, cooldown-suppressed and SMTP-failure cases.
- Confirmation rejects malformed, unknown, expired, replaced and reused
  tokens with identical public errors; password policy matches registration.
- Concurrent confirmation produces one winner without sleep-based sync.
- Password change and session/refresh revocation commit or roll back together;
  old access and refresh credentials fail after success, new login succeeds.
- Cooldown holds across concurrent requests and service replicas via PostgreSQL.
- SMTP failures and logs do not disclose addresses, tokens, or credentials.
- Preserve AUTH-01 through AUTH-05 behavior. Regenerate Swagger with pinned
  Swag; do not hand-edit generated files.
- Run project-required unit tests, `go vet`, `gofmt`, pinned golangci-lint,
  Linux race tests, disposable PostgreSQL 16 integration tests, Swagger diff
  check, Docker build and configured Trivy scan. Report commands and skips.

Add a STRIDE threat-model note for account enumeration, token theft/replay,
brute force, reset-email compromise, cooldown abuse, SMTP failure and
concurrent resets. Update README, `.env.example`, Auth architecture, task
status and journal to match implementation.

## Acceptance criteria

- A verified account owner can request a reset and change the password once.
- Public requests do not reveal whether an email belongs to an account.
- Only token digests are stored; tokens expire, are replaced, and are single-use.
- Password update and all-session revocation are atomic.
- Old credentials fail after success; a new login with the new password works.
- Tests, generated Swagger and required checks pass; no prior Auth behavior regresses.

## Delivery

Gemini submits the plan first. Codex reviews and approves that plan before code
starts. Explain each change in plain English with its purpose. Do not commit,
push or deploy without a separate user instruction.
