# Rules

## Go
- Standard library first. Small, justified dependencies only.
- Wrap errors with context: fmt.Errorf("doing x: %w", err).
- context.Context is the first argument of every I/O function.
- No global state. Inject dependencies through constructors.
- Interfaces are defined where they are used.
- gofmt and golangci-lint must pass.

## Code comments and explanations (user preference)
- Write code comments in plain English: why a decision exists,
  what it protects and what happens on failure. Avoid restating the code.
- Explain unfamiliar terms when they matter. Do not comment every line.
- Keep comments truthful and update them when behavior changes; exported GoDoc
  starts with the declared identifier. Do not hand-edit generated comments.
- For each reported change give purpose, location and verification result.
- Examples and AUTH-01 corrections: .ai/tasks/auth-01-review.md.

## Security (hard rules)
- Passwords: argon2id only. Never log passwords, tokens, or secrets.
- No secrets in code or git. Use env vars and Kubernetes secrets.
- Strictly forbidden to view, read, edit, or touch any local .env file (including .env, .env.*, or any secret environment file) or local signing keys / private key files (including /services/auth/keys/, *.pem, *.key). The developer manages their own .env files and local keys. The AI must never inspect, open, print, or modify them; only tracked templates like .env.example may be maintained.
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
  If a secret was staged, unstage it and tell the user. Never view, read, or edit .env files or local signing keys (/services/auth/keys/).
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
