# Current task

Stage 0, weeks 1-2: foundation.

## Step S0.2 - auth service skeleton (active)
No business logic. Dependencies: only github.com/go-chi/chi/v5
(approved in ADR 0002). Everything else is standard library.

Deliverables:
1. services/auth/cmd/auth/main.go
   - chi router
   - wires config, router, and server
   - config from env: HTTP_ADDR (default :8080)
   - server timeouts, graceful shutdown on SIGINT/SIGTERM
2. services/auth/internal/http
   - handlers for GET /healthz and GET /readyz
   - slog JSON logging
   - unit tests for handlers (go test ./... -race passes) alongside handlers
3. services/auth/go.mod (check the installed Go version, do not guess)
4. services/auth/Dockerfile: multi-stage, distroless static nonroot,
   CGO_ENABLED=0
5. .github/workflows/ci.yml: on push to main and PR, in services/auth:
   go test -race, golangci-lint, docker build, trivy scan
   (fail on HIGH and CRITICAL)
6. .githooks/pre-commit: block commit if files outside .ai/, docs/,
   README.md changed but .ai/journal.md or .ai/tasks/current.md
   was not updated
7. .ai updates per Memory rule

## Done
- Repo structure, .ai/, ADR 0001
- S0.1b: approve chi router (ADR 0002)

## Next (after S0.2)
- [ ] S0.3 GHCR image push
- [ ] S0.4 k3s on Oracle Cloud + Argo CD
- [ ] S0.5 Prometheus/Grafana + k6 baseline

## Notes
(session notes go here)