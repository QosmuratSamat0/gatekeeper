# AUTH-07 abuse hardening threat model

Scope: Client IP resolution behind trusted reverse proxies, registration IP rate limiting, and caller session validation on email verification resend.

| STRIDE category | Asset / boundary and threat | Mitigation | Residual risk |
|---|---|---|---|
| Spoofing | Untrusted caller spoofs `X-Forwarded-For` or `X-Real-IP` to bypass IP rate limits or blame arbitrary IPs. | Centralized `ClientIPResolver` ignores forwarding headers unless direct peer (`RemoteAddr`) is within `TRUSTED_PROXY_CIDRS`. When peer is trusted, traverses XFF right-to-left skipping trusted proxies and returns first untrusted hop. Malformed/missing headers safely fall back to `RemoteAddr`. | If an operator configures an untrusted subnet in `TRUSTED_PROXY_CIDRS`, callers from that subnet can spoof client IPs. |
| Tampering | Attacker rotates IPv6 addresses within their assigned `/64` prefix to bypass rate limits or exhaust in-memory limiter table. | Client IP key normalization masks all IPv6 addresses to their `/64` prefix, mapping entire subnet to a single rate limit bucket and table entry. IPv4-mapped IPv6 is unmapped to standard IPv4. | Attackers controlling multiple distinct `/64` allocations (or large IPv4 botnets) can still distribute attempts across distinct buckets. |
| Repudiation | Operator logs untrusted forwarded headers as client IP or logs sensitive authentication data. | Client IP resolver extracts deterministic, normalized IP; rate limiter logs contain request IDs and safe categories without logging passwords or tokens. | Upstream proxy logs remain managed under their own logging and retention configuration. |
| Information disclosure | Rate limit responses or error headers reveal internal proxy infrastructure or network topology. | Generic 429 `rate_limited` error envelope returned with `Retry-After`; internal proxy IPs in XFF chain are parsed in memory and never echoed in HTTP response bodies or headers. | Timing differences between rate limit rejection (pre-hash) and downstream processing are visible by design. |
| Denial of service | 1. Anonymous flood on `POST /v1/auth/register` exhausts shared Argon2id CPU/RAM hashing slots (default 2 concurrency) or exhausts SMTP quota. 2. Behind ingress, single attacker's requests lock out all users due to shared proxy IP. | 1. Dedicated `IPRateLimiter` applied to `POST /v1/auth/register` before body decoding and Argon2id hashing (default 5 attempts/min, returns 429 with `Retry-After`). 2. Trusted proxy resolver extracts actual client IP, isolating attackers to their own rate-limit buckets. | Distributed denial of service across broad IP ranges requires edge/gateway-level rate limiting (Stage 3 Gateway). |
| Elevation of privilege | Attacker uses a revoked, expired, or stolen access token to trigger email verification resend spamming (`POST /v1/auth/email/verification/request`). | Resend endpoint verifies active caller session via `currentAccountUC.Execute`, returning 401 `unauthorized` for revoked, expired, or non-existent sessions before issuing verification tokens or dispatching emails. | Valid active sessions can still trigger resend within the 60-second database-backed cooldown limit. |

## Relevant OWASP ASVS Areas
- **V2 Authentication**: V2.2.1 (Anti-automation and rate limiting on credential entry and registration).
- **V3 Session Management**: V3.2.1, V3.2.2 (Verifying active session state before processing sensitive operations).
- **V7 Error Handling and Logging**: Generic error messages, standard error codes, no internal network topology leakage.
- **V10 Malicious Code / Abuse Protections**: V10.2 (Automated attack mitigations, client IP resolution and proxy trust boundaries).

## Verification Tests
- Table-driven unit tests for `ClientIPResolver`: untrusted direct peer with spoofed XFF, trusted peer with single XFF, trusted peer with multi-hop chain, untrusted intermediate hop, malformed XFF, all-trusted XFF fallback, IPv6 `/64` prefix masking, IPv4-mapped IPv6 unmapping.
- Unit and HTTP rate limiting tests: verify `POST /v1/auth/register` returns 429 on request $N+1$ with `Retry-After`, and counting fake hasher confirms Argon2id is never invoked on rate-limited requests.
- Unit and integration tests for verification resend: revoked session (via logout-all or targeted revocation) returns 401 `unauthorized` and sends no email; active session succeeds with 202.
- Config validation tests: verify validation bounds for `REGISTER_RATE_LIMIT_ATTEMPTS`, `REGISTER_RATE_LIMIT_WINDOW`, and valid/invalid `TRUSTED_PROXY_CIDRS`.
