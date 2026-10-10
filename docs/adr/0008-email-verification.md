# ADR 0008: Email verification tokens and SMTP delivery

- Status: Accepted; implemented 2026-10-09 for AUTH-05.
- Deciders: User (scope owner); Codex prepares architecture; Gemini proposes the implementation plan.
- Context: Auth accounts already store `email_verified`, but registration does not verify mailbox ownership. Email verification must be added without weakening token handling or silently changing login behavior. The project prefers the standard library and has no approved email vendor/dependency.
- Decision proposed:
  1. Store only the SHA-256 digest of a 32-byte cryptographically random, canonical base64url one-time token. The raw token exists only in the delivery call and email.
  2. Expire tokens after 24 hours, allow one active token per account, and consume the token plus set `email_verified` in one PostgreSQL transaction. Recheck expiry after account-then-token locks.
  3. Deliver a plain-text copyable token using a consumer-owned `EmailSender` port and a Go standard-library SMTP adapter. Require STARTTLS and verified certificates; send SMTP credentials only after TLS, bound every operation, and never log recipient/token/body/credentials.
  4. Send after database commit so locks are not held during network I/O. If delivery fails after account creation, return a generic 503 and let the account owner log in and retry through an authenticated resend route. Document this recoverable partial-success case.
  5. Require an active Bearer session for resend; derive account identity from verified claims and database, accept no email/account ID in the request, and enforce a database-backed 60-second per-account cooldown. Confirmation stays public, rate-limited and returns identical invalid-token errors for every failure.
  6. Keep `email_verified=false` accounts able to log in and use current endpoints. Do not change JWTs, sessions, or authorization rules in AUTH-05.
- Consequences: No new third-party dependency or raw-token database storage is needed. SMTP availability becomes a registration dependency; the authenticated resend route recovers from transient delivery failure. A copyable token keeps the API/mobile contract independent of an unchosen web/mobile deep-link scheme. This does not claim that possession of an email address is a strong identity proof.
- Revisit if a product frontend, deep-link contract, asynchronous mail queue, or external provider is selected.
