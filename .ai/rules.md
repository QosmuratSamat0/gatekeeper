# Rules

## Go
- Standard library first. Small, justified dependencies only.
- Wrap errors with context: fmt.Errorf("doing x: %w", err).
- context.Context is the first argument of every I/O function.
- No global state. Inject dependencies through constructors.
- Interfaces are defined where they are used.
- gofmt and golangci-lint must pass.

## Security (hard rules)
- Passwords: argon2id only. Never log passwords, tokens, or secrets.
- No secrets in code or git. Use env vars and Kubernetes secrets.
- Do not invent cryptography. Use vetted libraries.
- Validate all input. Return generic errors on auth failures.
- Use constant-time comparison for secrets and tokens.
- Tokens: short-lived access tokens, rotating refresh tokens, revocation.
- Every new endpoint gets a threat-model note (see prompts/threat-model.md).

## Service standards
- Endpoints: /healthz, /readyz, /metrics.
- Structured JSON logs (slog) with request id.
- Graceful shutdown. Timeouts on all clients and servers.
- Config from environment only.

## Containers and Kubernetes
- Multi-stage Dockerfile, distroless base, non-root, read-only filesystem.
- Resource requests and limits on every pod.
- NetworkPolicy default deny.

## Process
- Architectural decisions go to docs/adr/ (short ADR).
- Tests are required for auth and authz logic.
- Never edit an applied migration; add a new one.
- Small commits, conventional commit messages.
- Do not add features outside the current stage.

## Git rules
- Never use git push --force, git commit --no-verify, git reset --hard
  on pushed commits, or rewrite history.
- If a hook blocks a commit, fix the cause (usually update
  .ai/journal.md and .ai/tasks/current.md). Never bypass the hook.
- Never commit secrets, .env files, keys, tokens, or build artifacts.
  If a secret was staged, unstage it and tell the user.
- Commit format (Conventional Commits):
  <type>(<scope>): <summary>

  Journal: <YYYY-MM-DD> <step id>
  Types: feat, fix, docs, chore, test, refactor, ci.
- One logical change per commit. Small commits.
- Push only to main for now (solo project). Do not create or delete
  branches or tags without asking.
- Do not change git config, remotes, or repository settings.

## Scope limits
- Standard library only unless a dependency is approved in an ADR.
- No features beyond the current step in .ai/tasks/current.md.
- Never delete files outside the current step's scope.
- If something unexpected happens (failing CI, merge conflict,
  unfamiliar files), stop and report instead of improvising.