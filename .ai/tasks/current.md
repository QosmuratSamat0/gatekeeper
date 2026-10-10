# Current task

## Current priority (2026-10-09)
- Done: record the Auth + Access target in architecture/auth-access.md.
- Done: record Gateway target and middleware boundaries in architecture/gateway.md.
- Auth first; Access implementation is deferred.
- Gemini writes code; Codex designs, prepares tasks and reviews results.
- Done: inspected Auth skeleton and prepared [AUTH-01](auth-01.md): registration,
  PostgreSQL account model, Argon2id, target layout and acceptance tests.
- Done: implemented AUTH-01 (registration, persistence, Argon2id, migrations, tests, OpenAPI).
- Done: addressed second-round review feedback in auth-01-review.md (server forced Close() on shutdown timeout with test, Argon2id context cancellation before/after slot acquisition with test, error categorization and secret scrubbing in register.go logs with test, isolated disposable DB per integration test with opt-in and sanitized URL, Swag single source of truth with DTO tags and CI check, real PostgreSQL 16 and Linux -race test execution evidence).
- Done: addressed third-round review feedback in auth-01-review.md (simplified logging with safe category and request ID without error text, client connection severed assertion in shutdown test, email_verified marked required in Swagger).
- Done: configured local development environment with services/auth/.env.example, gitignore protection for .env, secure PowerShell launcher run.ps1 (no Invoke-Expression, error masking, GOCACHE isolation, migrate and api runner), and README.md instructions.
- Done: updated minimum password length from 15 to 8 characters (validated 7 rejected, 8 accepted) across use case, Swag annotations, unit tests, and Swagger documentation.
- Done: integrated Swagger UI using ready-made library github.com/swaggo/http-swagger/v2 mounted at /swagger/* (with /swagger redirect) without custom HTML pages; generated api/docs.go via swag; updated ADR 0004, CI check, README, and unit tests.
- Done: [AUTH-02](auth-02.md) — login, access JWT, sessions, /me, logout, public JWKS:
  все замечания ревью Codex закрыты, полный набор проверок (gofmt, go vet, golangci-lint, unit tests, Docker build, Linux -race, PostgreSQL 16 integration tests) успешно пройден и подтверждён. AUTH-02 полностью принят.
- Done and accepted: **AUTH-03** — refresh-токены, их ротация, обнаружение повторного использования (reuse detection) и аннулирование семейства токенов при компрометации.
- Done: Codex prepared [AUTH-03](auth-03.md); user selected JSON refresh tokens for API/mobile clients.
- Done: утверждён план с двумя обязательными уточнениями (убрать сырой refresh из результата репозитория; проверять актуальное время после ожидания блокировок; зафиксирован исход гонки refresh vs logout). Принят ADR 0006.
- Done: реализована миграция `000003_create_refresh_tokens` (с проверками octet_length=32, временных порядков, частичным уникальным индексом).
- Done: реализованы токены (`ValidateAndHashRefreshToken` со строгим canonical RFC 4648 декодированием, `GenerateRefreshToken`, `SignAccessTokenWithExpiry` с отсечением и проверкой exp <= iat).
- Done: реализованы атомарные операции в репозитории `session.go` с каноническим порядком блокировок `accounts (SHARE) -> sessions (UPDATE) -> refresh_tokens (UPDATE)`, повторной проверкой состояния под блокировками и фиксацией компрометации в БД при reuse.
- Done: реализованы use cases (`LoginUsecase` с начальным refresh, `RefreshUsecase`, `LogoutUsecase` с `ExecuteByRefreshToken`).
- Done: реализованы HTTP-хэндлеры (`POST /v1/auth/refresh`, обновлён `POST /v1/auth/login`, двухрежимный `POST /v1/auth/logout` с отклонением 400 при неоднозначных учётных данных).
- Done: настроены независимые rate limiters (10/min/IP) для login, refresh и logout.
- Done: сгенерирована документация Swagger 2.0 (`swag init`) с DTO и аннотациями.
- Done: устранены 5 замечаний ревью Codex по AUTH-03:
  1. Usecase отвязан от конкретного адаптера: в `usecase/ports.go` введены consumer-owned порты `RefreshTokenGenerator`, `RefreshTokenValidator`, `RefreshTokenManager`, удалены импорты `platform/token` из `login.go`, `refresh.go`, `logout.go`, реализация подключена в `app/wiring.go`.
  2. Добавлена повторная проверка wall-clock времени непосредственно перед изменениями в `session.go` (предотвращает нарушение constraint `chk_refresh_tokens_expiry_order` и ошибку 500, возвращает generic 401 с rollback; также generic 401 возвращается при `domain.ErrSessionExpired` из signer).
  3. В `logout.go` исправлена проверка взаимоисключающих режимов: проверяется строгое наличие заголовка (`len(authHeaders) > 0`) независимо от содержимого (включая пустой заголовок + тело refresh), возвращается 400 `invalid_request`.
  4. Коды ошибок 400 в refresh и refresh-logout приведены к единому `invalid_request` (вместо `bad_request`); в тестах проверяется поле `code` в теле ответа.
  5. Тесты расширены и усилены:
     * Тест гонки `TestPostgres_Refresh_ConcurrentSameTokenRace` строго требует ровно 1 успех (`200 OK`) и ровно `numWorkers - 1` отказов (`401 Unauthorized`).
     * `TestPostgres_Refresh_SignerExpLeqIatRollback` детерминированно проверяет настоящий signer `TokenService.SignAccessTokenWithExpiry` при `exp <= iat` с использованием фиксированных часов signer'а при валидной сессии в БД; подтверждён вызов реального callback signer'а, возврат `domain.ErrSessionExpired` и откат мутаций в PostgreSQL.
     * `TestPostgres_Logout_DualModes` проверяет logout через refresh-токен после истечения access-токена, а также отклонение пустого `Authorization` с телом.
     * `TestPostgres_Refresh_SuccessorInsertFailureRollback` проверяет откат при ошибке вставки преемника и сохранение пригодности старого refresh-токена для последующего успешного refresh (200 OK).
  6. Добавлено правило `/services/auth/keys/` в корневой `.gitignore` с английским комментарием о недопустимости коммита локальных ключей подписи; работа правила подтверждена через `git check-ignore -v` (без открытия и вывода содержимого файлов ключей); в `.ai/rules.md` и `.ai/workflow.md` внесены явные запреты на просмотр, чтение, изменение и коммит локальных ключей подписи и каталога `/services/auth/keys/`.
- Done: повторно пройден и подтверждён полный цикл верификации:
  * Unit-тесты (`services/auth/internal/...`) — 100% pass.
  * `gofmt -l .` — 0 файлов (100% форматирование).
  * `go vet ./...` — 0 предупреждений.
  * `golangci-lint` (Docker `golangci/golangci-lint:latest`) — `0 issues`.
  * Linux race detector (`-race` в Docker `golang:1.26-alpine`) — 100% pass, 0 races.
  * PostgreSQL 16 интеграционные тесты — все 15 тестов успешно прошли на изолированной БД.
  * Docker build `gatekeeper-auth:ci` — успешно.
  * Trivy scan на собранном образе — 0 уязвимостей (0 HIGH, 0 CRITICAL).
- Done: Codex accepted AUTH-03; user confirmed manual API flow. Local signing keys are ignored and protected by AI rules.
- Done: [AUTH-04](auth-04.md) — own session listing (`GET /v1/auth/sessions`), targeted revocation (`DELETE /v1/auth/sessions/{session_id}`), and atomic account logout-all (`POST /v1/auth/logout-all`):
  * Migration `000004_sessions_keyset_index`: composite partial index `idx_sessions_account_active_keyset ON sessions (account_id, created_at DESC, id DESC) WHERE revoked_at IS NULL`.
  * Keyset cursor codec (`cursor.go`): canonical unpadded base64url encoding of `{"v":1,"c":"...","i":"..."}`, strict rejection of trailing bytes (secondary decode expecting EOF), validation of version, UUID hex format, and rejection of timestamp precision loss exceeding PostgreSQL microseconds.
  * Live single-statement listing in PostgreSQL (`session.go`): CTEs with `clock_timestamp()`, caller verification via `EXISTS (SELECT 1 FROM caller)` preventing scalar subquery NULL return, expiry check against single transaction timestamp, and outer `ORDER BY p.created_at DESC NULLS LAST, p.id DESC NULLS LAST`.
  * Pre-lock ownership filtering in targeted revocation: `WHERE account_id = $1 AND id IN ($2, $3)` with deterministic ascending UUID sorting preventing deadlocks.
  * Explicit distinction between caller authentication failure (401 `unauthorized`, `ErrCallerSessionNotFound`) and target session failure (404 `session_not_found`, `ErrSessionNotFound`). Idempotent 204 for already revoked/expired owned targets.
  * Deadlock-free concurrent opposite-direction revocation (Session A revoking B vs Session B revoking A): winner receives 204, loser receives 401; only the loser's session is revoked.
  * Atomic `POST /v1/auth/logout-all`: serializes via account `FOR UPDATE`, locks unrevoked sessions in ascending UUID order, verifies caller session row, and revokes with `clock_timestamp()`.
  * HTTP endpoints enforce `Cache-Control: no-store` and strict empty payload policy (413 if > 4 KiB, 400 `invalid_request` if non-empty body).
  * Generated Swagger 2.0 API docs (`docs.go`, `swagger.json`, `swagger.yaml`).
  * Unit tests and integration test suites implemented with 100% pass rate.
  * ADR 0007 recorded in `docs/adr/0007-session-management-and-concurrency.md` and `.ai/decisions.md`.
  * Verified in-transaction overlap and PostgreSQL lock wait (`pg_locks WHERE NOT granted`) without sleeps for concurrent refresh vs. logout-all, refresh vs. single-revoke, and login vs. logout-all across both transaction interleavings.
  * Moved transaction fault injection to test-only wrappers around `PgxPoolExecutor` and `pgx.Tx`, removing test fields and hooks from production code.
  * Verified in-flight mutation rollback in PostgreSQL for single session revocation and logout-all.
  * Successfully executed full verification pipeline with active Docker daemon and PostgreSQL 16:
    - Unit tests (`services/auth/...`) — 100% pass.
    - PostgreSQL 16 integration tests (`RUN_INTEGRATION_TESTS=true`) — 100% pass.
    - `golangci-lint` (Docker `golangci/golangci-lint:latest`) — 0 issues.
    - Linux race detector (`-race` in Docker `golang:1.26-alpine`) — 100% pass, 0 data races.
    - Docker build `gatekeeper-auth:ci` — 100% success.
    - Trivy vulnerability & secret scan — 0 vulnerabilities (0 HIGH, 0 CRITICAL), 0 secrets.
    - `gofmt -l .` — 0 unformatted files.
    - `go vet ./...` — clean.
    - Git workspace clean of `.cache/` (using `.gocache/`).
- Accepted (2026-10-09): AUTH-04 passed the user's manual API verification: sessions list 200; logout-all 204; revoked caller token correctly rejected with 401; fresh login and owned-session revocation returned 200/204. No commit or push authorized.
- Done (2026-10-09): [AUTH-05](auth-05.md) — Email verification implementation completed and verified:
  * Migration `000005_create_email_verification_tokens`: bounded storage table `email_verification_tokens` with `account_id UUID PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE`, SHA-256 binary `token_hash bytea NOT NULL UNIQUE`, and `expires_at TIMESTAMPTZ NOT NULL`.
  * Token engine (`email_verification.go`): 32 cryptographically random bytes encoded as unpadded 43-character base64url; 32-byte SHA-256 digest calculated and stored. Raw token never persisted to disk or logged.
  * Robust SMTP delivery platform (`smtp.go`): standard library `net/smtp` implementation with mandatory STARTTLS, verified TLS certificates (`InsecureSkipVerify: false`), credentials sent strictly after TLS handshake, 10s timeout watcher and socket deadline.
  * Decoupled consumer-owned ports (`ports.go`): `EmailSender`, `EmailVerificationTokenGenerator`, `IssueVerificationTokenResult`, `EmailVerificationRepository`.
  * Transactional PostgreSQL repository (`email_verification.go`): canonical row locking order (account row lock `FOR UPDATE` first, then token row lock) preventing deadlocks; atomic consumption deleting token and marking `email_verified = true`; 60s cooldown enforcement under row lock across replicas; strict `clock_timestamp() < expires_at` check.
  * Post-commit registration email delivery: registration DTO unchanged; SMTP failure returns 503 `service_unavailable` while account remains created and active (`email_verified = false`), recoverable via authenticated resend.
  * Public confirmation (`POST /v1/auth/email/verification/confirm`): in-memory IP rate limiting (10 req/min/IP); returns 204 on success; identical 400 `invalid_verification_token` with standard error envelope (`code`, `message`, `request_id`) across all invalid token cases (expired, superseded, wrong format, consumed, unknown); database errors and timeouts preserved as 500/503 (never masked as 400).
  * Authenticated resend (`POST /v1/auth/email/verification/request`): requires active Bearer session; derives account ID from verified JWT session; accepts empty body only (400 if non-empty, 413 if > 4 KiB); returns 202 `{"status":"accepted"}`; enforces DB-backed 60s cooldown; already-verified accounts safely return 202 without issuing tokens or emails.
  * Swagger 2.0 specs regenerated (`docs.go`, `swagger.json`, `swagger.yaml`).
  * Unit tests (`services/auth/internal/...`) pass 100%.
  * PostgreSQL 16 integration tests: 22/22 suites pass, including real `pg_locks` lock-wait test for superseded confirmation race, concurrent 10-worker race (1 winner, 9 invalid), cooldown replacement, and boundary expiration.
  * Complete container verification suite passed:
    - `gofmt -l .` — clean (0 unformatted files).
    - `go vet ./...` — clean.
    - `golangci-lint` (Docker v2.14.0) — 0 issues.
    - Linux race detector (`-race` in Docker `golang:1.26-alpine`) — 100% pass, 0 data races.
    - Docker build `gatekeeper-auth:ci` — success (exit 0).
    - Trivy security scan (`aquasec/trivy:latest`) — 0 vulnerabilities (0 HIGH, 0 CRITICAL), 0 secrets.
    - `git diff --check` — clean.
- Done (2026-10-10): addressed review feedback on request cancellation ordering:
  * In `services/auth/internal/delivery/http/email_verification.go`, reordered error checking: moved `context.Canceled` check above `domain.ErrVerificationEmailFailed` (mirroring `register.go:114`), preventing spurious 503 response and email delivery failure logging if the client cancels during SMTP dispatch.
  * Added unit tests in `services/auth/internal/delivery/http/email_verification_test.go` verifying that client-side cancellation during email transmission and direct usecase `context.Canceled` write no body and do not return 503.
  * Re-verified full test suite: unit tests (100%), PostgreSQL integration tests (22/22), `golangci-lint` (0 issues), Linux `-race` (0 data races), Docker build, and Trivy scan (0 findings).
- Accepted (2026-10-10): User manually tested the AUTH-05 email verification flow and confirmed it works. AUTH-04/AUTH-05 implementation is committed as `4d29ab8`; not pushed.
- Prepared: [AUTH-06](auth-06.md) — password recovery by email. Proposed policy is recorded in ADR 0009 and its threat-model note. Gemini must present a plan; user approval is required before implementation.
- Done: AUTH-04/AUTH-05 committed as `4d29ab8`; push remains pending separate user authorization.
- Next: Review and approve the final AUTH-06 plan before coding.

## Previous foundation task (pending)
Stage 0, weeks 1-2: foundation.

## Step S0.3 - GHCR image push (pending)
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
