# Commands

## Go (from services/<name>)
go build ./...
go test ./... -race
golangci-lint run

## Docker
docker build -t gatekeeper-auth:dev services/auth
docker run --rm -p 8080:8080 gatekeeper-auth:dev

## Load test
k6 run tests/load/login.js

## Kubernetes
kubectl get pods -A
argocd app list

## Infra
cd infra && tofu plan && tofu apply
