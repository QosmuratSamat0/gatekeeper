# Current task

## Current priority (2026-10-04)
- Done: record the Auth + Access target in architecture/auth-access.md.
- Done: record Gateway target and middleware boundaries in architecture/gateway.md.
- Auth first; Access implementation is deferred.
- Gemini writes code; Codex designs, prepares tasks and reviews results.
- Done: inspected Auth skeleton and prepared [AUTH-01](auth-01.md): registration,
  PostgreSQL account model, Argon2id, target layout and acceptance tests.
- Done: implemented AUTH-01 (registration, persistence, Argon2id, migrations, tests, OpenAPI).
- Done: addressed second-round review feedback in auth-01-review.md (server forced Close() on shutdown timeout with test, Argon2id context cancellation before/after slot acquisition with test, error categorization and secret scrubbing in register.go logs with test, isolated disposable DB per integration test with opt-in and sanitized URL, Swag single source of truth with DTO tags and CI check, real PostgreSQL 16 and Linux -race test execution evidence).
- Done: addressed third-round review feedback in auth-01-review.md (simplified logging with safe category and request ID without error text, client connection severed assertion in shutdown test, email_verified marked required in Swagger).
- Done: configured local development environment with services/auth/.env.example, gitignore protection for .env, secure PowerShell launcher run.ps1 (no Invoke-Expression, error masking, GOCACHE isolation, migrate and api runner), and README.md instructions.
- Done: updated minimum password length from 15 to 8 characters (validated 7 rejected, 8 accepted) across use case, Swag annotations, unit tests, and Swagger documentation.
- Done: integrated Swagger UI using ready-made library github.com/swaggo/http-swagger/v2 mounted at /swagger/* (with /swagger redirect) without custom HTML pages; generated api/docs.go via swag; updated ADR 0004, CI check, README, and unit tests.
- Done: [AUTH-02](auth-02.md) — login, access JWT, sessions, /me, logout, public JWKS:
  все замечания ревью Codex закрыты, полный набор проверок (gofmt, go vet, golangci-lint, unit tests, Docker build, Linux -race, PostgreSQL 16 integration tests) успешно пройден и подтверждён. AUTH-02 полностью принят.
- Current task: **AUTH-03** — refresh-токены, их ротация, обнаружение повторного использования (reuse detection) и аннулирование семейства токенов при компрометации.
- Done: Codex prepared [AUTH-03](auth-03.md); user selected JSON refresh tokens for API/mobile clients. Browser cookie authentication is deferred.
- Next: Gemini presents the AUTH-03 implementation plan (migration, transaction ports, lock order, HTTP contracts and tests) for Codex review before writing code.
- User authorized committing and pushing the accepted AUTH-01/AUTH-02 work and AUTH-03 brief on 2026-10-06. AUTH-03 implementation still awaits plan review.
- Delivery: baseline commit 8a3b8d9 created; record hash and whitespace cleanup before pushing to origin/main.
- Refresh rotation is AUTH-03; Access/Gateway remain later work.
- Follow-up: make Swagger UI explicitly configurable (SWAGGER_ENABLED).

## Previous foundation task (pending)
Stage 0, weeks 1-2: foundation.

## Step S0.3 - GHCR image push (pending)
Build and push auth service container image to GitHub Container Registry (GHCR) on push to main with appropriate tagging.

Deliverables:
1. Update CI/CD workflow to authenticate with GHCR and push container images
2. Verify image publishing and run
3. .ai updates per Memory rule

## Done
- Repo structure, .ai/, ADR 0001
- S0.1b: approve chi router (ADR 0002)
- S0.2: auth service skeleton, tests, Dockerfile, CI workflow

## Next (after S0.3)
- [ ] S0.4 k3s on Oracle Cloud + Argo CD
- [ ] S0.5 Prometheus/Grafana + k6 baseline

## Notes
(session notes go here)
