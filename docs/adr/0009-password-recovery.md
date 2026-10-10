# ADR 0009: Password recovery by email

- Status: Proposed for AUTH-06; requires user approval before implementation.
- Deciders: User owns product scope; Codex prepares architecture; Gemini proposes an implementation plan.
- Context: Auth needs a way for an account owner who forgot a password to regain access. The service already has verified email, an injected SMTP sender, Argon2id hashing, sessions and rotating refresh tokens.
- Proposed decision:
  1. Provide public request and confirmation endpoints. Return the same generic `202 Accepted` for every syntactically valid request email to reduce account enumeration.
  2. Send reset messages only to active accounts with verified email. Do not change `email_verified` during password recovery.
  3. Use a one-time 32-byte random base64url token; persist only its SHA-256 digest; expire after 30 minutes; allow one current token per account.
  4. Apply bounded IP rate limits and a PostgreSQL-backed 60-second account cooldown.
  5. In one PostgreSQL transaction, consume the token, update the Argon2id password hash and revoke all active sessions/refresh credentials. Keep the existing canonical lock order and recheck token expiry after locks.
  6. Deliver email asynchronously via an in-process bounded dispatcher (channel of 8 slots + pool of 4 workers) using a dedicated application worker context. Remote SMTP I/O is excluded from the HTTP response path so clients receive generic 202 immediately. On queue overflow, tasks are dropped without blocking and logged safely while generic 202 is preserved. On graceful shutdown, drain waits up to 45 seconds for in-flight tasks to complete before closing the database pool, requiring deployment terminationGracePeriodSeconds >= 75s. External message brokers (Kafka, Redis, RabbitMQ) remain out of scope.
  7. Keep SMTP I/O outside database transactions and never log addresses, tokens, passwords, email contents, or SMTP credentials.
- Consequences: Reset emails go only to verified addresses; a reset cannot silently verify an address. Generic request responses reduce probing. The in-process dispatcher removes macroscopic SMTP latency from HTTP responses, but does not guarantee eliminating timing differences between existing and non-existing accounts due to database operations (residual timing side-channel remains). Task drops on queue overflow or abrupt process crashes are mitigated by user retry after the 60s cooldown. Successful resets require all devices to log in again, though existing access JWTs remain valid until exp in services validating only signatures via JWKS. Token lifetime/cooldown values remain proposed until the user approves the design.
- Revisit if the product chooses another recovery factor, a persistent transactional outbox / distributed message queue, or a different user experience.
