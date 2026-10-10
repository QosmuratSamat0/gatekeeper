# Gatekeeper Auth Service

The `auth` service handles identity registration and credential persistence for Gatekeeper.

## Scope (AUTH-01 through AUTH-06)
- Account registration with email and password (`POST /v1/auth/register`).
- User authentication and session issuance (`POST /v1/auth/login`).
- Authenticated account profile retrieval (`GET /v1/auth/me`).
- Idempotent session revocation (`POST /v1/auth/logout`).
- Active sessions listing (`GET /v1/auth/sessions`) with keyset pagination.
- Targeted session revocation (`DELETE /v1/auth/sessions/{session_id}`).
- Account logout-all revocation (`POST /v1/auth/logout-all`).
- Email verification request (`POST /v1/auth/email/verification/request`) and confirmation (`POST /v1/auth/email/verification/confirm`).
- Password reset request (`POST /v1/auth/password-reset/request`) with generic 202 anti-enumeration response and bounded in-process asynchronous dispatch.
- Password reset confirmation (`POST /v1/auth/password-reset/confirm`) with atomic credential update, session revocation, and generic 400 error.
- Public JSON Web Key Set projection (`GET /.well-known/jwks.json`).
- Asymmetrically signed access JWTs via Ed25519 / EdDSA (RFC 8037).
- Secure password hashing and verification with Argon2id and shared concurrency limit.
- Per-IP rate limiting (10 attempts/minute) on public endpoints.
- Storage in PostgreSQL with schema migrations via `cmd/migrate`.
- Health (`/healthz`) and database readiness (`/readyz`) probes.

## Architecture
- `cmd/api`: HTTP server entry point with graceful signal shutdown.
- `cmd/migrate`: Database migration runner (`up`, `version`).
- `internal/domain`: Domain entities (`Account`, `Session`) and typed domain errors.
- `internal/usecase`: Use cases (`Register`, `Login`, `CurrentAccount`, `Logout`, `ListSessions`, `RevokeSession`, `LogoutAll`, `EmailVerification`, `PasswordRecovery`) and consumer ports.
- `internal/delivery/http`: Chi router, HTTP handlers, strict DTO validation, Bearer auth, IP rate limiting, and standardized error responses.
- `internal/repository/postgres`: Parameterized PostgreSQL repositories with transactional session creation, keyset pagination, and atomic token operations.
- `internal/platform`: Configuration, PostgreSQL connection pool, Argon2id hasher/verifier, Ed25519 JWT token manager, and SMTP email client.
- `migrations`: Versioned SQL migrations (`000001` through `000006`).
- `api/`: Generated API contracts via Swag (Go code annotations are the single source of truth).

## Configuration
| Variable | Default | Description |
| --- | --- | --- |
| `HTTP_ADDR` | `:8080` | Bind address for HTTP server |
| `DATABASE_URL` | *(required)* | PostgreSQL connection URL |
| `DB_CONNECT_TIMEOUT` | `5s` | Timeout for establishing database connection and health pings |
| `DB_QUERY_TIMEOUT` | `3s` | Query execution timeout |
| `HTTP_SHUTDOWN_TIMEOUT` | `10s` | Timeout for graceful shutdown before closing connections |
| `PASSWORD_HASH_CONCURRENCY` | `2` | Maximum concurrent Argon2id hashing/verification operations per instance (1-32) |
| `JWT_ISSUER` | `gatekeeper-auth` | Token issuer string (`iss`) |
| `JWT_AUDIENCE` | `gatekeeper-services` | Token audience string (`aud`) |
| `JWT_ACTIVE_KID` | `gatekeeper-key-1` | Active key ID for token header and JWKS |
| `JWT_PRIVATE_KEY_FILE` | *(required)* | Path to PKCS#8 Ed25519 private key PEM file |
| `JWT_PUBLIC_KEYS_FILE` | *(optional)* | Path to optional archived public keys JWKS JSON file for key rotation |
| `ACCESS_TOKEN_TTL` | `10m` | Access token duration (1m to 15m) |
| `LOGIN_RATE_LIMIT_ATTEMPTS` | `10` | Maximum login attempts per IP per window |
| `LOGIN_RATE_LIMIT_WINDOW` | `1m` | Window duration for IP rate limiting |
| `PASSWORD_RESET_TOKEN_TTL` | `30m` | Password reset token lifetime (5m to 24h) |
| `PASSWORD_RESET_COOLDOWN` | `60s` | Cooldown between password reset requests for an account (10s to 10m) |
| `PASSWORD_RESET_QUEUE_DRAIN_TIMEOUT` | `45s` | Graceful shutdown drain timeout for in-process email delivery queue |

## Local Development

### 1. Set Working Directory and Configure Environment
Navigate to the auth service directory and copy the environment template to `.env` (excluded from Git):
```powershell
Set-Location services/auth
Copy-Item .env.example .env
```

### 2. Generate Developer Signing Key
Generate an Ed25519 private key in PKCS#8 PEM format for local development (do not commit this key):
```powershell
New-Item -ItemType Directory -Force -Path keys | Out-Null
openssl genpkey -algorithm ed25519 -out keys/ed25519_private.pem
```
Set `JWT_PRIVATE_KEY_FILE=keys/ed25519_private.pem` in your local `.env`.
Adjust credentials in `.env` if needed. Default settings bind database and API strictly to `127.0.0.1` on port `5432`.

### 2. Start PostgreSQL
Run a local PostgreSQL 16 container bound strictly to loopback (`127.0.0.1:5432`):
```powershell
docker run -d `
  --name gatekeeper-postgres `
  -p 127.0.0.1:5432:5432 `
  -e POSTGRES_USER=gatekeeper `
  -e POSTGRES_PASSWORD=secretpassword `
  -e POSTGRES_DB=gatekeeper_auth `
  postgres:16-alpine
```

### 3. Wait for Database Readiness
Wait until PostgreSQL is healthy and accepting connections before running migrations:
```powershell
Write-Host "Waiting for PostgreSQL to accept connections..."
do {
    Start-Sleep -Seconds 1
    docker exec gatekeeper-postgres pg_isready -U gatekeeper -d gatekeeper_auth 2>$null | Out-Null
} until ($LASTEXITCODE -eq 0)
Write-Host "PostgreSQL is ready."
```

### 4. Run Migrations
Apply database migrations using the isolated PowerShell runner (loads `.env` and restores shell environment on exit):
```powershell
.\run.ps1 migrate up
```

To verify the applied schema version:
```powershell
.\run.ps1 migrate version
```

### 5. Start the API Service
Run the Auth service HTTP API (bound to `127.0.0.1:8080`):
```powershell
.\run.ps1 api
```

### 6. Verify Health Probes and Swagger UI
```powershell
Invoke-RestMethod -Uri http://127.0.0.1:8080/healthz
Invoke-RestMethod -Uri http://127.0.0.1:8080/readyz
```
*(Or via curl:)*
```bash
curl -i http://127.0.0.1:8080/healthz
curl -i http://127.0.0.1:8080/readyz
```

Interactive Swagger UI documentation is available at:
`http://127.0.0.1:8080/swagger/index.html` (or redirect via `http://127.0.0.1:8080/swagger`).
Raw Swagger 2.0 JSON specification is available at:
`http://127.0.0.1:8080/swagger/doc.json`.

## Security Tradeoffs & Residual Risks
1. **Account Enumeration**: Duplicate registration returns `409 account_exists`. This explicitly exposes whether an email address is already registered in exchange for immediate user feedback.
2. **Rate Limiting**: Distributed rate limiting and brute-force protection are planned for the Gateway/Access layers. This registration endpoint must not be exposed to the public internet without an upstream reverse proxy or gateway providing abuse protection.
3. **No Tokens or Login**: AUTH-01 only creates and persists account credentials. Issuing tokens, session management, and login flows belong to subsequent tasks.
