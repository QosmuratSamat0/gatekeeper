# Architecture

## Stack
- Language: Go
- HTTP: net/http + chi
- DB: Postgres (pgx, golang-migrate)
- Cache/limits: Redis
- Events: Kafka or NATS JetStream (from stage 4)
- Service-to-service: gRPC (later), HTTP for now
- Platform: k3s on Oracle Cloud ARM, Terraform/OpenTofu
- Delivery: GitHub Actions -> GHCR -> Argo CD (GitOps)
- Observability: Prometheus, Grafana, OpenTelemetry, slog (JSON)
- Load testing: k6

## Layout
- services/<name>/   one Go module per service
- deploy/            Helm charts or Kustomize manifests
- infra/             Terraform/OpenTofu
- docs/adr/          architecture decision records

## Service layout (Go)
cmd/<name>/main.go
internal/{http,service,store,config}
migrations/
Dockerfile

## Request flow (target)
client -> gateway (token check, rate limit) -> service
gateway/services -> authz.check(user, relation, object)
all services -> audit events