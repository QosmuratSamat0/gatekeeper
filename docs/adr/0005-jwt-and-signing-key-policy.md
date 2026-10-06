# ADR 0005: JWT Library Selection, Ed25519 Signing, and Key Management Policy

## Status
Accepted

## Context
Step AUTH-02 introduces short-lived access tokens, session persistence, and token-based authentication for Gatekeeper.
Key architectural and security considerations:
1. **JWT Library Selection & Vulnerability Analysis**:
   - We evaluated `github.com/golang-jwt/jwt/v5` across released versions.
   - Security advisory CVE-2025-30204 (CWE-405) identified an asymmetric resource consumption and memory exhaustion vulnerability in versions prior to `v5.2.2` during unverified header parsing.
   - Security advisory CVE-2024-51744 highlighted improper error prioritization when tokens were both expired and had invalid signatures.
   - Consequently, versions prior to `v5.2.2` (including `v5.2.1`) are strictly rejected. We pin `v5.3.1`, which resolves all reported CVEs, incorporates strict parsing options, and is fully compatible with our Go 1.26 toolchain.
2. **Cryptographic Algorithm**:
   - Standardize on **Ed25519 (alg: EdDSA)**. Ed25519 provides 128-bit security, immune to timing side-channels, with small key sizes (32 bytes public, 64 bytes private) and rapid signature generation/verification without complex curve parameters.
3. **Key Management & Storage**:
   - The signing private key is loaded at startup from an external PKCS#8 PEM file specified by `JWT_PRIVATE_KEY_FILE`.
   - The private key is runtime secret material: it is never committed to Git, never read by AI assistants, and never generated as an ephemeral in-memory key on production startup.
   - Public keys are published via a standard JWKS endpoint (`/.well-known/jwks.json`, RFC 7517 / RFC 8037).
   - Key rotation is supported via an active key ID (`JWT_ACTIVE_KID`) and an optional public key set file containing previous keys. Old public keys are retained for at least token TTL (10m) + clock skew (30s) + JWKS cache TTL (60s).

## Decision
1. **Dependency Pinning**:
   - Use `github.com/golang-jwt/jwt/v5 v5.3.1`.
2. **Access Token Specifications**:
   - **Header**: `{"alg": "EdDSA", "typ": "JWT", "kid": "<active-key-id>"}`.
   - **Claims**:
     - `sub`: Subject account ID (UUID v4 string).
     - `sid`: Persisted session ID (UUID v4 string).
     - `iss`: Configured token issuer string (exact match).
     - `aud`: Configured token audience string (exact match).
     - `iat`: Numeric issued-at timestamp (seconds).
     - `exp`: Numeric expiration timestamp (`iat + ACCESS_TOKEN_TTL`, default 10m, bounded 1–15m).
     - `jti`: Unique token identifier (UUID v4 string).
   - Strictly no roles, permissions, passwords, or PII in the access token.
3. **Verification Policy**:
   - Pinned algorithm: strictly accept `EdDSA`. Explicitly reject `alg: none`, HMAC algorithms, and RSA algorithms to prevent algorithm substitution attacks.
   - Explicit `kid`: reject tokens with missing, empty, or unknown key IDs.
   - Claim presence: require `typ == "JWT"`, `exp`, `iat`, `sub`, `sid`, `iss`, `aud`, and `jti`.
   - Temporal validation: enforce `exp > iat`, reject future `iat` (beyond allowable clock skew), and enforce expiry with at most 30 seconds clock skew tolerance.
   - Trust boundary: do not follow or trust remote key URLs (`jku`, `x5u`) or embedded client keys.
4. **JWKS Projection**:
   - Implement `GET /.well-known/jwks.json` serving standard RFC 7517 / RFC 8037 format:
     `{"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "<base64url>", "kid": "<id>", "use": "sig"}]}`.
   - Header: `Cache-Control: public, max-age=60`.
   - Never expose private key components or metadata.

## Consequences
- (+) High cryptographic security with Ed25519 / EdDSA without risk of curve-parameter or timing vulnerabilities.
- (+) Protection against known CVEs (CVE-2025-30204, CVE-2024-51744) by selecting and pinning `v5.3.1`.
- (+) Independent public verification: external microservices and API gateways can verify tokens autonomously using the JWKS endpoint without access to the private signing key.
- (+) Strict token structure prevents algorithm confusion, missing-claim bypasses, and token replay outside valid time windows.
- (-) Asymmetric signing requires managing PEM files and key rotation procedures.
