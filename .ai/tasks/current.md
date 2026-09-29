# Current task

Stage 0, weeks 1-2: foundation.

## Step S0.3 - GHCR image push (active)
Build and push auth service container image to GitHub Container Registry (GHCR) on push to main with appropriate tagging.

Deliverables:
1. Update CI/CD workflow to authenticate with GHCR and push container images
2. Verify image publishing and run
3. .ai updates per Memory rule

## Done
- Repo structure, .ai/, ADR 0001
- S0.1b: approve chi router (ADR 0002)
- S0.2: auth service skeleton, tests, Dockerfile, CI workflow

## Next (after S0.3)
- [ ] S0.4 k3s on Oracle Cloud + Argo CD
- [ ] S0.5 Prometheus/Grafana + k6 baseline

## Notes
(session notes go here)