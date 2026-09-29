# Journal

### 2026-09-29 12:00 - S0.1 - repo skeleton
- Done: created monorepo structure, .ai/, ADR 0001
- Files: README.md, .ai/*, docs/adr/0001-*.md
- Decisions: Go + monorepo (ADR 0001)
- Problems: none
- Next: auth skeleton with /healthz
- Commit: 46ac517

### 2026-09-29 00:55 - S0.1b - approve chi router
- Done: approved chi router, documented in ADR 0002, updated decisions index and S0.2 deliverables
- Files: docs/adr/0002-use-chi-router.md, .ai/decisions.md, .ai/tasks/current.md
- Decisions: use github.com/go-chi/chi/v5 for route grouping and middleware (ADR 0002)
- Problems: none
- Next: execute step S0.2 (auth service skeleton)
- Commit: 86a6228

### 2026-09-29 21:10 - S0.2 - auth service skeleton
- Done: implemented auth skeleton with chi router, /healthz and /readyz endpoints, slog JSON logging with request ID, graceful shutdown, unit tests, multi-stage distroless Dockerfile, and GitHub Actions CI workflow
- Files: services/auth/cmd/auth/main.go, services/auth/internal/http/handlers.go, services/auth/internal/http/handlers_test.go, services/auth/Dockerfile, .github/workflows/ci.yml
- Decisions: use chi router per ADR 0002; avoid deprecated middleware.RealIP
- Problems: realip deprecated due to IP spoofing, excluded from router middleware; git .github file converted to directory
- Next: S0.3 GHCR image push
- Commit: pending