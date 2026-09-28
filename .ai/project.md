# Project

Gatekeeper is an identity and access platform built from scratch.
Goal: a really usable set of security microservices with production-grade
operations (Kubernetes, observability, load testing), and a strong
engineering portfolio.

## Services (planned)
- auth: registration, login, OIDC, MFA (TOTP, WebAuthn)
- authz: Zanzibar-style relationship-based access checks
- gateway: token validation, rate limiting
- audit: append-only event log
- kyc: identity document verification, eGov/NCALayer integration

## Roadmap
- [ ] Stage 0: foundation (CI, k3s, GitOps, observability)
- [ ] Stage 1: auth
- [ ] Stage 2: authz
- [ ] Stage 3: gateway and rate limiting
- [ ] Stage 4: audit and hardening
- [ ] Stage 5: KYC
- [ ] Stage 6: SDK, docs, demo app

## Principles
- Each stage ends with a public result: code, README, load test numbers.
- Implement standards (OAuth 2.1, OIDC, WebAuthn), do not invent protocols.
- Start simple, split later. No premature microservices.
- Measure everything: RPS, p99, failure behavior.

## Status
Current stage: 0. See tasks/current.md.