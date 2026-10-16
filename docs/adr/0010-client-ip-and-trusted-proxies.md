# ADR 0010: Client IP resolution and trusted proxy boundaries

- Status: Accepted (implemented in AUTH-07).
- Deciders: User, Claude (audit and task specification), Gemini (implementation).
- Context:
  When Auth runs behind a Kubernetes ingress or reverse proxy (such as k3s in S0.4), `r.RemoteAddr` reflects the immediate proxy rather than the original client. If rate limiters key solely on `RemoteAddr`, all clients share a single rate-limit bucket, enabling trivial denial of service against legitimate users. Conversely, unconditionally trusting client-supplied headers like `X-Forwarded-For` or `X-Real-IP` (as done by `chimiddleware.RealIP`) allows attackers to spoof arbitrary IP addresses and bypass rate limiting. Additionally, IPv6 clients can cycle through addresses in an allocated `/64` subnet to flood the in-memory limiter table (10,000 entries), and unauthenticated endpoints like registration lacked rate limiting before invoking expensive Argon2id hashing.
- Decision:
  1. Implement a single centralized `ClientIPResolver` in `delivery/http/middleware`. All HTTP rate limiters delegate to this resolver; no limiter reads HTTP headers directly.
  2. Configure trusted reverse proxies via `TRUSTED_PROXY_CIDRS` (comma-separated CIDR strings, default empty). If the configuration is empty or the direct connection peer (`RemoteAddr`) is not within a trusted subnet, all forwarding headers are ignored and `RemoteAddr` is used directly.
  3. When the direct peer is trusted, parse `X-Forwarded-For` and traverse addresses from right to left, skipping trusted proxy hops. The first untrusted IP encountered is returned as the client IP.
  4. If `X-Forwarded-For` is missing, malformed, or contains only trusted addresses, resolution safely falls back to `RemoteAddr`. Do not support `X-Real-IP` or `Forwarded` in this service.
  5. Normalize client IP keys before rate limiting:
     - IPv4 addresses are keyed directly as-is.
     - IPv4-mapped IPv6 addresses (`::ffff:x.x.x.x`) are unmapped and keyed as IPv4.
     - IPv6 addresses are masked to their `/64` network prefix, grouping all addresses in the same standard SLAAC/routing subnet into one rate-limit bucket.
  6. Apply a separate `IPRateLimiter` to `POST /v1/auth/register` before body decoding and Argon2id hashing (default 5 attempts/minute, configurable via `REGISTER_RATE_LIMIT_ATTEMPTS` [1–1000] and `REGISTER_RATE_LIMIT_WINDOW`). Return 429 `rate_limited` with standard error envelope and `Retry-After` header.
  7. Enforce caller session validity on `POST /v1/auth/email/verification/request`: verify active session via existing `currentAccountUC.Execute` and return 401 `unauthorized` if the session is revoked, expired, or not found. Keep `BearerAuth` middleware unchanged so `POST /v1/auth/logout` preserves idempotent revocation.
- Consequences:
  Enables safe deployment behind Kubernetes ingress and reverse proxies without exposing rate limits to header spoofing. Prevents table exhaustion from IPv6 rotation attacks. Protects Argon2id CPU and memory resources from unauthenticated registration floods. Requires operators to explicitly configure `TRUSTED_PROXY_CIDRS` to match their ingress pod/node subnets when deploying behind proxies.
