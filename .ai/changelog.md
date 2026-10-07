# Changelog

- f226159 2026-10-07 feat(auth): implement rotating refresh tokens and reuse detection - Atomic JSON refresh rotation, persistent reuse revocation, dual-mode logout, PostgreSQL migration/tests, signing-key protection and AUTH-04 brief.

- d563dba 2026-10-06 fix(auth): upgrade vulnerable Go dependencies - Updated pgx and Go x modules after Trivy findings; security scanner remains enabled.

- 8a3b8d9 2026-10-06 feat(auth): implement registration and session authentication - Accepted AUTH-01/AUTH-02, application wiring, PostgreSQL persistence, Argon2id, JWT/JWKS, session logout, generated Swagger, CI/integration tests and AUTH-03 JSON refresh brief.

- <hash> <date> <message> - <what changed in architecture/behavior>
- 86a6228 2026-09-29 docs: approve chi router, update step S0.2 - Approved chi router (ADR 0002) and updated S0.2 task definition
- a7fa38b 2026-09-29 feat(auth): implement service skeleton, health endpoints, and CI - Added chi router, /healthz and /readyz, slog JSON logging, graceful shutdown, unit tests, distroless Dockerfile, and GitHub Actions CI workflow
