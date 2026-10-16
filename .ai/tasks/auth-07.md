# AUTH-07 — Abuse hardening before deployment

Status: prepared by Claude on 2026-10-16 from the project audit. Gemini
implements; Claude reviews. Gemini must post a short written plan and wait for
approval before coding. No commit, push or deployment is authorized by this task.

## Goal

Close the abuse gaps found in the audit before Auth runs behind a k3s ingress
(S0.4). Keep every existing API contract, except the documented 429 response
added to registration.

## Problems to fix

1. `POST /v1/auth/register` has no rate limit. The Argon2id hash runs before the
   duplicate-email check and shares the hasher semaphore (default 2 slots) with
   login and password-reset confirm. An anonymous flood therefore blocks login
   for everyone and sends verification emails to arbitrary addresses.
2. `RateLimitMiddleware` keys on `r.RemoteAddr` only. Behind an ingress every
   client shares one address, so one attacker locks out all users. IPv6 clients
   can rotate addresses inside one /64 and fill the 10,000-entry table, after
   which the limiter refuses every new IP.
3. `POST /v1/auth/email/verification/request` accepts an access token for a
   revoked or expired session. Swagger already documents 401 for that case, but
   the code does not check it.

## Scope

### 1. Registration rate limit
- Apply the existing `IPRateLimiter` to `/v1/auth/register` before body decoding
  and hashing. Use a separate limiter instance, as other endpoints do.
- Configurable via `REGISTER_RATE_LIMIT_ATTEMPTS` (default 5, range 1-1000) and
  `REGISTER_RATE_LIMIT_WINDOW` (default 1m). Validate the values the same way as
  `LOGIN_RATE_LIMIT_*` in `platform/config/config.go`.
- Response: 429 `rate_limited` with `Retry-After`, the same envelope as other
  limited routes. Add it to the Swagger annotations.

### 2. Client IP resolution behind trusted proxies
- Add a single client-IP resolver in `delivery/http/middleware`. Every limiter
  uses it; no limiter reads headers itself.
- Config: `TRUSTED_PROXY_CIDRS` is a comma-separated CIDR list, empty by default.
  - Empty means the current behaviour: use `RemoteAddr` and ignore all forwarding
    headers.
  - Only when the direct peer (`RemoteAddr`) is inside a trusted CIDR, walk
    `X-Forwarded-For` from right to left, skipping trusted addresses. The first
    untrusted address is the client.
  - If the header is missing, malformed, or contains only trusted addresses, fall
    back to `RemoteAddr`. Never trust the left-most value blindly. Do not support
    `Forwarded` or `X-Real-IP` in this task.
  - Invalid CIDR config fails startup with a clear error and no secret content.
- Normalise the limiter key: IPv4 is used as is, IPv6 is masked to its /64
  prefix, and IPv4-mapped IPv6 is treated as IPv4.
- Do not use `chimiddleware.RealIP`: it trusts headers unconditionally.

### 3. Session check on verification resend
- Make `RequestEmailVerification` reject a revoked, expired or unknown caller
  session with 401 `unauthorized`, matching `/v1/auth/me` and the session routes.
  Reuse the existing session lookup; do not add a new query if one fits.
- Do not change `BearerAuth` itself. Logout must keep accepting revoked sessions
  idempotently.

## Out of scope
- Distributed or Redis-backed rate limiting (that belongs to the Gateway, see
  architecture/gateway.md).
- Per-account login lockout, CAPTCHA, breached-password checks.
- Registration enumeration (409), password-reset griefing, session/token row
  cleanup, Argon2 parameter rehashing, CI image-scan changes. These are recorded
  in the audit and will be separate tasks.
- Kubernetes manifests or ingress configuration.

## Tests (required)
- Unit, client IP resolver, table-driven:
  - no trusted CIDRs plus a spoofed XFF gives `RemoteAddr`;
  - a trusted peer with a single XFF value gives that value;
  - a trusted peer with a chain `spoofed, client, trusted-proxy` gives `client`;
  - an untrusted peer with XFF gives `RemoteAddr`;
  - a malformed XFF, or one with only trusted addresses, gives `RemoteAddr`;
  - two IPv6 addresses in the same /64 give the same key, a different /64 gives
    a different key;
  - `::ffff:1.2.3.4` gives the same key as `1.2.3.4`.
- Unit, config: defaults, valid and invalid `TRUSTED_PROXY_CIDRS`, and the
  `REGISTER_RATE_LIMIT_*` bounds.
- HTTP: request N+1 to register returns 429 with `Retry-After`, and the hasher is
  never invoked for the rejected request (use a counting fake).
- HTTP and integration: verification resend with the access token of a session
  revoked via logout-all returns 401 and sends no email. An active session still
  gets 202.
- Existing XFF-spoofing tests keep passing with the default (empty) config.

## Docs and memory
- Update `services/auth/.env.example` and `services/auth/README.md` with the new
  variables and an explicit warning: set `TRUSTED_PROXY_CIDRS` only to the
  ingress or proxy network.
- Add a threat-model note for the client-IP trust boundary
  (`.ai/prompts/threat-model.md`).
- Write an ADR, `docs/adr/0010-client-ip-and-trusted-proxies.md`, and add a line
  to `.ai/decisions.md`.
- Regenerate Swagger with pinned swag v1.16.4.
- Follow the Memory rule: `.ai/journal.md`, `.ai/tasks/current.md`.

## Acceptance criteria
- `go test ./... -race` (Linux/Docker), `go vet ./...`, `gofmt -l .`,
  golangci-lint v2.14.0, Docker build and `git diff --check` are clean.
- PostgreSQL 16 integration tests pass with `RUN_INTEGRATION_TESTS=true`.
- With default config, behaviour is identical to today except for the new
  register limit and the verification-resend session check.
- No `.env` file or signing key is read, printed or committed.

## Report back to Claude
List the changed files, the decisions made, and any deviation from this task
with its reason. Include the command output summaries for every check above,
plus open questions.
