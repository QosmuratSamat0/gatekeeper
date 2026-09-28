Create a new Go service named <name> following .ai/rules.md and
.ai/architecture.md.
Include: service layout, config, /healthz /readyz /metrics, slog logging,
graceful shutdown, Dockerfile, Helm/Kustomize manifests in deploy/,
CI workflow update, and a first ADR if a decision was made.
Do not implement business logic beyond what is requested.