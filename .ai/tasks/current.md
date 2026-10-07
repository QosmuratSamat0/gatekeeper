# Current task

## Current priority (2026-10-04)
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
- Current task: [AUTH-04](auth-04.md) ? own session listing, targeted revocation and logout-all. Gemini presents a plan before implementation.
- Delivery: user authorized AUTH-03 commit/push on 2026-10-07; implementation committed as f226159; record commit and push pending.

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
