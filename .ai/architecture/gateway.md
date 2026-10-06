# Gateway target architecture

Recorded 2026-10-04. Target design only; Gemini implements code.
Auth remains the first implementation priority.

## Responsibilities
- Public HTTP entry point: explicit routing to Auth and business services.
- Validate JWTs on protected routes using Auth JWKS: approved algorithms,
  signature, issuer, audience and expiry. Never possess Auth signing keys.
- Apply CORS, request/body limits, timeouts, rate limits, request IDs and tracing.
- Reverse proxy requests and consistently report gateway/upstream errors.
- Do not implement login, password handling, role storage, permission decisions
  or object ownership rules. Services remain responsible for those operations.
- No database or migrations initially. Redis is an optional adapter for shared
  rate limits across replicas, with an explicit failure policy before rollout.

## Layout
```text
services/gateway/
  cmd/api/main.go
  internal/
    app/{app.go,wiring.go}
    delivery/http/
      router.go
      errors.go
      middleware/         # JWT, CORS, request ID, limits, recovery
    routing/              # explicit route table and public/protected policies
    proxy/                # net/http/httputil reverse proxy and HTTP transport
    platform/
      config/
      identity/           # JWT verification and bounded JWKS cache
      ratelimit/          # limiter interface and chosen adapter
      observability/
  api/openapi.yaml        # gateway-owned endpoints/behavior, not copied APIs
  go.mod
  Dockerfile
```
Use net/http + chi. Domain/usecase/repository layers are unnecessary until
there is a real responsibility requiring them. Keep routing separate from
proxy mechanics and authentication middleware; inject dependencies in app.

## Request flow
Client -> Gateway -> target service -> Access when a permission check is needed.
Target services validate forwarded bearer JWTs themselves. Gateway strips
client-supplied identity headers; X-User-ID and similar headers are never an
authentication source. Private services accept only intended trusted traffic,
but network isolation does not replace token/service credential validation.
Internal Access checks use service credentials and are not public proxy routes.
Access administration may be exposed only through explicit protected routes;
Access itself authorizes administrative actions.

## Middleware boundaries
| Gateway | Auth / business service |
| --- | --- |
| General request/IP limits | Account-specific login limits and abuse rules |
| JWT validation at the edge | JWT validation and operation authorization |
| Browser CORS | Session, refresh-cookie and CSRF checks where applicable |
| Edge body limits and timeouts | Endpoint limits and database/client timeouts |
| Request ID and edge tracing | Service tracing, safe logs, error mapping |

Login, registration, recovery and JWKS have explicitly public routes: no
access JWT requirement, but request limits still apply. Refresh/logout policies
depend on Auth's session contract; they must not accidentally require a valid
access JWT when refresh-session credentials are the intended authentication.
Liveness/readiness are available on the intended operational interface;
metrics are not broadly exposed through public service routing.

## Security and reliability
- Upstreams come from validated configuration, never user-provided URLs.
  Unknown routes are denied. Restrict forwarded headers and trust proxy/IP
  headers only from configured trusted ingress addresses.
- Preserve cookies and Authorization only for their intended upstreams.
  Do not log tokens, credentials, cookies or auth request bodies.
- TLS at the edge; protect internal transport according to deployment trust
  boundaries. Set connect, header, idle and request timeouts and pool limits.
- JWKS cache is bounded; key refreshes are rate-limited. Reject unverifiable
  tokens, including unknown keys that cannot be fetched. Account for rotation.
- No automatic retry of login, refresh, writes or other non-idempotent calls.
- Return 502 for upstream connection/protocol failures, 504 for upstream
  timeout, 429 for exceeded limits. Do not expose upstream internal errors.
- Stateless replicas; graceful shutdown and health/readiness/metrics.
- Define long-lived connection policies separately if WebSocket/streaming is
  added; ordinary request timeouts must not silently break those protocols.

## Delivery
Design Auth contracts first. Implement a minimal Gateway once Auth can be
integrated; expand explicit routes as services arrive. Access follows the
recorded RBAC design. Concrete tasks require ADRs, threat-model notes and tests
for route protection, spoofed headers, JWT failures and proxy failure behavior.
