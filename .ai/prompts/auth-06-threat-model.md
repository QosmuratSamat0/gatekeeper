# AUTH-06 password recovery threat model

Use this note to review the implementation plan and final code. Keep the
review tied to these concrete risks and controls.

| Threat | Required control | Evidence |
| --- | --- | --- |
| Account enumeration | Same public status/body for all valid email requests; in-process async email dispatch decouples remote SMTP latency from HTTP response. Residual timing risk remains due to database query differences between existing and missing accounts; approaches to reduce it must be evaluated separately | HTTP tests for existing, missing, unverified and suppressed accounts; timing analysis review |
| Token theft or replay | Cryptographically random token, digest-only storage, short expiry, single-use transaction | Token tests and PostgreSQL consume/replay tests |
| Token guessing | High-entropy token and bounded confirmation rate limits | Configuration review and rate-limit tests |
| Mailbox compromise | Reset email contains only the one-time token and clear expiry; successful reset revokes sessions | Email test and session-revocation integration test |
| SMTP outage / queue drop | Generic public response, safe logs, defined retry/cooldown behavior; tasks dropped on queue overflow or process crash recoverable after 60s cooldown | Failure-path tests, overflow tests, and log assertions |
| Cooldown bypass | Account cooldown enforced by PostgreSQL, not per-process memory | Multi-worker/concurrent database test |
| Deadlock or partial reset | Documented canonical lock order and one transaction for password, token and sessions | Concurrent reset tests and rollback tests |
| Secret exposure | Never log raw token, password, email body, or SMTP credentials | Log-capture tests and code review |
