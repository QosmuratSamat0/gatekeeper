# ADR 0011: Scan the published image before promoting `latest`

- Status: Accepted (implemented in AUTH-07b/S0.3b).
- Deciders: User, Claude.
- Context:
  The S0.3 workflow scanned a local single-arch `gatekeeper-auth:ci` build, then
  rebuilt and pushed a different multi-arch image with `latest` in the same step.
  The published `linux/arm64` image (the Oracle Cloud target) was never scanned,
  and the Trivy action was referenced by the mutable `@master` branch.
- Decision:
  1. Push only the immutable `sha-<commit>` tag first.
  2. Scan that exact pushed manifest digest with Trivy for `linux/amd64` and
     `linux/arm64` (HIGH/CRITICAL, fixed only), pulling from the registry.
  3. Move `latest` to the scanned digest with `docker buildx imagetools create`
     only after both scans pass, and verify that `latest` resolves to it.
  4. Pin `aquasecurity/trivy-action` by commit SHA (v0.36.0, Trivy v0.70.0).
  5. Attach Buildx SLSA provenance and SBOM attestations explicitly.
- Consequences:
  `latest` and digests used for deployment always refer to a scanned image. A
  failed scan can leave a `sha-<commit>` tag that never becomes `latest`; such
  tags must not be deployed. Attestation manifests appear in the image index as
  `unknown/unknown` entries, which registries and Kubernetes ignore.
