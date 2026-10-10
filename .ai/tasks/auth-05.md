# AUTH-05 — Email verification

Status: task prepared by Codex on 2026-10-09. Proposed design choices are recorded in ADR 0008 for Gemini plan review. Gemini must present the implementation plan before coding. No implementation, commit, push or deployment is authorized by this task.

## Goal

Let an account owner verify the email address on their account using a short-lived, single-use token delivered by email. Preserve the AUTH-01 registration response shape and the current AUTH-02 policy: an active account with `email_verified=false` may still log in and use Auth. Verification changes the account flag; it does not introduce authorization roles or change JWT claims.

## Scope and boundaries

In scope:
- Create and store verification token digests, expire and consume tokens atomically, and set `accounts.email_verified=true`.
- Send a plain-text verification message through a consumer-owned `EmailSender` port and a configured SMTP adapter.
- Send an initial verification message after registration; allow an authenticated account to request another message.
- Add bounded request limits, tests, generated Swag docs, README/.env.example instructions, a threat-model note and ADR 0008.

Out of scope:
- Blocking login or protected operations until email verification.
- Password recovery, MFA, Access roles, Gateway, Redis, an asynchronous email queue/outbox, HTML templates, frontend/mobile deep-link handling, external email vendor SDKs, and account-email changes.
- Reading or changing a real `.env` file or local signing keys.

Keep `cmd/api/main.go` thin, wire adapters in `internal/app/wiring.go`, define narrow ports in `internal/usecase`, and keep SQL in `internal/repository/postgres`. Add a new migration; never edit migrations already applied.

## HTTP contract

All routes use the existing strict JSON decoder, request ID/error envelope, request-size limits, cancellation and error mapping. Responses containing account or token state use `Cache-Control: no-store`. Generate Swagger with the pinned Swag command; do not hand-edit generated API files.

### Registration change

Keep `POST /v1/auth/register` request and success response unchanged. After creating the account, issue a verification token and send it to the account email. The account remains active and `email_verified=false` until confirmation. Login remains available.

Email delivery happens after database writes commit; do not hold SQL locks or a transaction open during SMTP network I/O. If delivery fails, return the existing generic 503 error and log only a safe failure category and request ID. The account may already exist because registration and remote email delivery cannot commit atomically. The user can log in and use the authenticated resend route below. Document this recoverable partial-success behavior in README and tests.

### Request a verification email

`POST /v1/auth/email/verification/request` — requires exactly one valid Bearer access JWT and an active account/session, following `/me` conventions. It accepts no body and derives account ID/email only from the verified identity and database. Never accept an email address or account ID from the caller.

- Return `202 Accepted` with a fixed generic body for an already verified account and for an unverified account whose request is suppressed by cooldown; do not disclose whether a message was sent.
- For an eligible unverified account, persist a new token digest and expiry, then send the email after commit.
- On SMTP failure return generic `503 service_unavailable`. This route is authenticated, so it cannot be used to probe other accounts.
- Apply a database-backed 60-second per-account resend cooldown so it works across service replicas. Do not use an in-memory-only account cooldown.
- Reject a non-empty body with the existing 400 policy and preserve the 4 KiB body bound.

### Confirm the email

`POST /v1/auth/email/verification/confirm` — public, rate-limited by the existing bounded per-IP mechanism.

Request: `{"token":"<43-character canonical unpadded base64url token>"}`

- `204 No Content` on first successful confirmation.
- For unknown, malformed, expired, already used, superseded or otherwise invalid tokens return the same `400 invalid_verification_token` status and message. Never say whether an account exists.
- Reject malformed JSON, unknown fields, trailing JSON, oversized bodies and empty tokens using existing input conventions.
- A repeated confirmation is invalid; it must not change state again.

## Token and persistence policy

- Generate 32 random bytes from `crypto/rand`; encode as canonical, unpadded RFC 4648 base64url (43 characters).
- The raw token is delivered once and never stored, logged, returned from the Auth API, or included in errors. Store only its SHA-256 digest as 32 bytes in PostgreSQL.
- Default token lifetime: 24 hours, bounded configuration with a documented safe range. Compare expiry using database wall-clock time after acquiring locks.
- At most one unconsumed, unrevoked token per account. Issuing a replacement invalidates the previous token. Persist a resend timestamp/cooldown in a concurrency-safe way; concurrent requests must not bypass it.
- Confirmation is one transaction: identify the account for the digest, acquire locks in the documented account-then-token order, recheck token status and expiry after locks, consume the token and mark the account verified. Concurrent confirmation attempts yield exactly one 204; others receive the generic invalid-token result. Roll back both changes on any failure.
- Add constraints and indexes that enforce token digest size, one-active-token policy and lookup by digest. State explicit retention behavior; do not add an unbounded cleanup worker in this task. Never edit prior migrations.
- Do not invalidate sessions or alter existing JWTs as a side effect of email verification.

## Email delivery and configuration

Add an `EmailSender` interface where the use case consumes it. The SMTP adapter belongs in `internal/platform/email` and is wired only in `app/wiring.go`.

Use Go's standard library first. SMTP must require STARTTLS and certificate/hostname validation; fail closed if STARTTLS is unavailable. If authentication is configured, send credentials only after TLS is established. Bound dialing and the complete SMTP operation with context/deadline and close connections on cancellation. Send a plain-text message containing the one-time token and a short expiry/instructions; do not put the token in a URL, query string, logs or metrics. Do not log message body, recipient address, password or SMTP response text.

Add documented environment configuration to `.env.example` only (never inspect the real `.env`): SMTP address, optional username/password, sender address, token TTL and resend cooldown. Validate settings at startup and explain how to run a local SMTP catcher such as Mailpit. Do not add a third-party dependency without a separate ADR and user approval.

## Architecture, tests and threat model

Before coding, Gemini presents a short plan covering:
1. Consumer-owned ports and use-case boundaries — so business rules do not import SMTP or SQL adapters.
2. Request/confirm DTOs, response/error behavior and generated Swag annotations — so clients get a stable contract.
3. Migration, account/token lock order, resend cooldown and post-commit SMTP flow — so replay and parallel requests cannot leave inconsistent state.
4. SMTP configuration, TLS and timeout handling — so credentials are protected and remote mail cannot hang request handlers.
5. Unit, HTTP and PostgreSQL tests and the threat-model cases — so security behavior is directly verified.

Required tests:
- Token generation is canonical, random and exactly 32 bytes before encoding; repository stores only the digest.
- Initial registration sends one email while keeping the existing response DTO and unverified-login behavior.
- A delivery failure returns safe 503 behavior without losing the recoverable account; authenticated resend can recover after cooldown.
- Resend requires a valid live account session, does not accept caller-supplied email/account ID, does not send for verified accounts, and honors the database-backed cooldown across concurrent requests.
- Confirmation succeeds once; malformed/unknown/expired/replaced/used tokens have the same public status and message; wrong account state does not become verified.
- PostgreSQL 16 concurrent confirmations produce exactly one success; resend-versus-confirm and transaction failures preserve the stated invariants; no sleeps for race synchronization.
- SMTP tests prove STARTTLS is mandatory, certificate/name failures abort, credentials are not sent before TLS, timeouts terminate work, and logs/errors do not disclose secrets.
- Preserve all AUTH-01 through AUTH-04 behavior and existing integration tests.

Use generated temporary test keys and fake SMTP servers; never use local signing keys. Run the project-required unit tests, go vet, gofmt, pinned golangci-lint v2.14.0, Linux race tests, disposable PostgreSQL 16 tests, Swagger regeneration diff check, Docker build and configured Trivy scan. Report exactly which commands ran and which were skipped.

Add a STRIDE threat-model note for email token theft/replay, account enumeration, email delivery compromise, token brute force, resend abuse, SMTP credential exposure and concurrent requests. Update Auth architecture, README and task status. Code comments must use plain English and explain why a check exists and which failure it prevents.

## Acceptance criteria

- A newly registered user receives a verification message when SMTP succeeds; API response schema remains compatible.
- Only the current account owner can request another message; fixed responses and rate limits resist probing and abuse.
- A valid token verifies exactly its own account once and within its lifetime; only its digest is persisted.
- SMTP requires authenticated TLS certificate validation, bounded timeouts and safe failure behavior.
- Unverified accounts may still log in; no role, token-claim, Gateway or Access behavior is added.
- Required tests and checks above pass, generated Swagger matches, and .ai/README/ADR/threat-model records agree with actual behavior.

## Delivery

Gemini first submits the implementation plan for Codex review. Do not write code before plan approval. Explain each proposed change in plain language before making it and report its purpose, location and verification afterward. Update `.ai/tasks/current.md` and append `.ai/journal.md`. Do not commit, push or deploy without a separate user instruction.
