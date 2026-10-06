# Auth and Access target architecture

Approved direction: 2026-10-04. This is a target design, not a description
of implemented features. Start with Auth; implement Access later.

## Responsibilities
- Auth: accounts, password hashing, login, sessions, token issuance,
  refresh rotation, logout, email verification and password recovery.
- Access: scopes (projects/organizations), arbitrary roles, permissions,
  role-permission links, user role assignments and authorization checks.
- Business services: validate Auth tokens, request permissions from Access,
  and enforce ownership and other rules for their own resources.
- Each service owns its database and migrations. No cross-service SQL.
- Auth does not hardcode business roles. Access uses Auth account IDs.

## Shared service layout
```text
services/<auth|access>/
  cmd/api/main.go
  cmd/migrate/main.go
  internal/
    app/{app.go,wiring.go}
    domain/
    usecase/             # operations and consumer-owned ports.go
    delivery/http/      # router, handlers, DTOs, error mapping, middleware
    repository/postgres/
    platform/           # config, technical adapters, observability
  migrations/
  api/openapi.yaml
  go.mod
  Dockerfile
```
Keep main.go thin. HTTP -> usecase -> domain; usecases depend on interfaces
implemented by repositories/adapters. Domain does not import HTTP or SQL.
Use net/http + chi as already approved, not Gin. Pass context.Context through
all I/O and enforce timeouts. Split files when useful, not as empty scaffolding.

## Auth
- Current implementation uses generated api/{docs.go,swagger.json,swagger.yaml}
  from Swag annotations (Swagger 2.0), superseding the layout's openapi.yaml.
- Next slice: [AUTH-02](../tasks/auth-02.md), login/access JWT/session/logout/JWKS.
  Refresh tokens are deliberately not issued until AUTH-03 implements rotation.
- Domain: account, session, domain errors.
- Usecases: register, login, refresh, logout, password reset.
- Storage: accounts, sessions, password reset and email verification tokens.
- API target: POST /v1/auth/{register,login,refresh,logout},
  POST /v1/auth/password-reset/{request,confirm},
  GET /.well-known/jwks.json.
- Argon2id passwords; short-lived asymmetrically signed access JWTs with
  subject, session ID, issuer, audience and expiry. No business roles initially.
- Opaque random refresh tokens; store hashes, rotate atomically, detect reuse
  and revoke the associated token family. Logout revokes refresh sessions;
  issued access JWTs remain valid until expiry unless additional revocation
  checks are explicitly introduced.
- Browser refresh-cookie and CSRF policy must be specified before implementing
  browser authentication. Key rotation and token validation rules also need
  an explicit design before implementation.

## Access (later)
- Storage: scopes, roles, permissions, role_permissions, role_assignments,
  audit_events. Assignments bind account + scope + role.
- Permission codes are stable and namespaced, e.g. learning.course:update.
- API target: scoped role management, permission bindings, assignment/revocation,
  POST /v1/check and POST /v1/check-batch.
- Check input: subject_id, scope_id, permission; output: allowed boolean.
- Start with RBAC, not a generic policy engine or Zanzibar implementation.
- Protect management operations; bootstrap the initial administrator through
  a controlled process. Restrict checks to authenticated, authorized callers.
- No permission match means deny. If Access is unavailable, protected
  operations fail closed and return a service-unavailable error.
- Object ownership stays with business services in this initial design.

## Cross-service flow and operations
Gateway is the public entry point; see [Gateway](gateway.md). Middleware lives
in both Gateway and services, with different responsibilities. Gateway checks
JWTs at the edge; services independently protect their operations.
Login -> Auth returns tokens. Business service validates JWT locally using
Auth JWKS, asks Access for permission, then enforces object rules.
Separate service credentials identify callers of Access; the business service
derives the user ID from verified credentials, never untrusted request input.
Replicas share durable storage and signing-key configuration, not in-memory
sessions. Distributed login limits may use Redis when required.
Use structured logs without secrets, health/readiness, metrics and graceful
shutdown. Cache authorization decisions only with an explicit revocation policy.

## Collaboration
- User owns priorities and approves implementation scope.
- Codex is the architect: designs, contracts, threat models, Gemini task briefs,
  code review and verification reports. Codex does not write implementation code
  unless the user changes this arrangement.
- Gemini writes implementation code and runs the required checks.
- Next: inspect the existing Auth skeleton and prepare one concrete, bounded
  Auth implementation task for Gemini. This document does not start that task.
