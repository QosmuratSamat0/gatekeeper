# 0001: Use Go and a monorepo

## Status
Accepted

## Context
Platform of several security services on Kubernetes, high-load focus.

## Decision
Use Go for services (performance, small static binaries, Kubernetes
ecosystem). Keep all services in one monorepo for atomic changes, shared
tooling, and simpler CI at this stage.

## Consequences
+ Fast builds, easy deployment, strong ecosystem for operators later.
+ Single place for docs and CI.
- Need path-based CI filtering as services grow.
