# S0.3 — Publish the Auth image to GHCR

## Goal
Publish a tested Gatekeeper Auth container image to GitHub Container Registry
(GHCR) after changes are pushed to `main`. The existing CI checks must still
run for pull requests, without publishing images from pull requests.

## Current state
- `.github/workflows/ci.yml` tests Auth, builds `gatekeeper-auth:ci`, and scans
  that local image with Trivy.
- `services/auth/Dockerfile` already supports Buildx target OS/architecture
  arguments and builds a non-root distroless image.
- The project deployment plan targets Oracle Cloud ARM, so the published image
  must support both `linux/amd64` and `linux/arm64`.
- The repository is `QosmuratSamat0/gatekeeper`; GHCR image references must use
  a lowercase owner and image name.

## Scope
- Update `.github/workflows/ci.yml` to publish the Auth image to
  `ghcr.io/qosmuratsamat0/gatekeeper-auth`; the registry path uses the lowercase
  GitHub owner.
- Keep tests, Docker build, and Trivy scan as required checks before publishing.
- Publish only after CI succeeds on a push to `main`. Pull requests must never
  log in to GHCR or publish an image.
- Use the workflow-provided `GITHUB_TOKEN`; do not add a personal access token
  or repository secret for registry login.
- Grant only `contents: read` to checkout/build steps and `packages: write` to
  the publishing job.
- Publish `linux/amd64` and `linux/arm64` manifests with commit-specific
  `sha-<commit>` and moving `latest` tags. For strict immutable deployments,
  recommend the published manifest digest (`ghcr.io/qosmuratsamat0/gatekeeper-auth@sha256:...`).
- Verify that the published image can be pulled by commit tag as well as manifest
  digest and that the registry manifest lists both target platforms. Run the image
  smoke check using temporary test configuration only; do not read local `.env`
  files or signing keys.

## Out of scope
- Kubernetes deployment, Argo CD, cloud infrastructure, or repository/package
  visibility changes.
- Changing Auth application behavior, migrations, or Docker runtime design.
- Publishing images for pull requests, branches other than `main`, or manually
  supplied arbitrary tags.

## Implementation plan for Gemini
1. Preserve the existing test and Trivy gates. Put image publishing in a
   separate job that depends on the successful Auth CI job and has a condition
   limited to `push` on `main`.
2. Configure Buildx for the two required platforms, authenticate with
   `GITHUB_TOKEN`, and publish the lowercase GHCR image path with commit-specific
   SHA and `latest` tags. Keep registry credentials scoped to the publishing job.
3. Add a verification step in CI giving the build step `id: build`, verifying image
   pull and multi-arch manifest by both commit tag and manifest digest
   (`${{ steps.build.outputs.digest }}`), and writing image metadata to
   `$GITHUB_STEP_SUMMARY`. Use only ephemeral test dependencies and generated test
   credentials if starting the service is required; never use or print local credentials
   or signing keys.
4. Document the image name, tag meanings (clarifying that `sha-<commit>` identifies
   source and recommending manifest digests for strict immutable deployments), and
   pull/run commands in the root README or service README, whichever currently owns
   container usage docs.
5. Update `.ai/tasks/current.md`, `.ai/journal.md`, and relevant architecture or
   deployment docs after implementation. Do not change architecture unless the
   actual delivery design changes.

## Acceptance criteria
- Pull request CI runs tests, Docker build, and Trivy, but performs no registry
  login and pushes no image.
- A push to `main` publishes only after all required CI checks pass.
- The GHCR image has a commit-specific `sha-<commit>` tag and a `latest` tag, and its
  manifest supports `linux/amd64` and `linux/arm64`.
- The exact commit-tagged image and manifest digest reference can be pulled and
  pass the documented verification.
- No registry credential is stored in repository secrets or printed in logs.
- `git diff --check` and the relevant workflow validation pass.
- Gemini reports the workflow run URL, image digest, published tags, manifest
  platforms, smoke-check result, and changed files.

## Open implementation detail
Choose a maintained Buildx publishing action/version consistent with the
repository's workflow conventions. Review its permissions and pinning before
use; do not guess action commit hashes.
