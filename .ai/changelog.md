# Changelog

- e4d9326 2026-10-11 feat(auth): implement password recovery by email (AUTH-06) - Bounded in-process delivery dispatcher, SHA-256 digest tokens, STARTTLS SMTP delivery, PostgreSQL migration and transactional repository, Argon2id password reset, session revocation, Swagger docs, concurrency hardening, and workflow_dispatch trigger.

- ce5d5d6 2026-10-10 fix(auth-06): keep generated Swagger output stable - Excluded generated swagger.json from EOF normalization, aligned the artifact to Swag v1.16.4, and clarified residual timing risk.

- 9f79d87 2026-10-10 docs(auth-06): align recovery proposal with async delivery - Updated the recovery task, ADR, and threat model for bounded in-process email delivery and its residual risks.
- b709210 2026-10-10 chore(dev): add local secret and push checks - Added Gitleaks and file hygiene hooks plus the Auth Go test suite on pre-push.

- 4d29ab8 2026-10-10 feat(auth): add session management and email verification - Added AUTH-04 session listing/revocation/logout-all and AUTH-05 email verification with digest-only tokens, STARTTLS delivery, migrations, tests, and generated Swagger.

- f226159 2026-10-07 feat(auth): implement rotating refresh tokens and reuse detection - Atomic JSON refresh rotation, persistent reuse revocation, dual-mode logout, PostgreSQL migration/tests, signing-key protection and AUTH-04 brief.

- d563dba 2026-10-06 fix(auth): upgrade vulnerable Go dependencies - Updated pgx and Go x modules after Trivy findings; security scanner remains enabled.

- 8a3b8d9 2026-10-06 feat(auth): implement registration and session authentication - Accepted AUTH-01/AUTH-02, application wiring, PostgreSQL persistence, Argon2id, JWT/JWKS, session logout, generated Swagger, CI/integration tests and AUTH-03 JSON refresh brief.

- <hash> <date> <message> - <what changed in architecture/behavior>
- 86a6228 2026-09-29 docs: approve chi router, update step S0.2 - Approved chi router (ADR 0002) and updated S0.2 task definition
- a7fa38b 2026-09-29 feat(auth): implement service skeleton, health endpoints, and CI - Added chi router, /healthz and /readyz, slog JSON logging, graceful shutdown, unit tests, distroless Dockerfile, and GitHub Actions CI workflow
