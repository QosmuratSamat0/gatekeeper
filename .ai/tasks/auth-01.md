# AUTH-01: account persistence and registration

Status: implementation brief, 2026-10-04. Gemini implements; Codex reviews.
User priority: Auth first. Reference ../architecture/auth-access.md.

## Пошаговые действия для Gemini с комментариями

Выполняй шаги последовательно. Перед каждым шагом коротко объясняй пользователю,
что делаешь и зачем; после шага сообщай результат проверки. Комментарии ниже
объясняют задание, а не требуют комментировать каждую строку исходного кода.

1. Прочитай `.ai/workflow.md`, правила, архитектуру и существующий Auth.
   Комментарий: сначала установи фактическое состояние проекта, чтобы сохранить
   работающие health endpoints, middleware и завершение сервера.
2. Представь короткий план и оформи ADR для новых зависимостей.
   Комментарий: pgx, миграции и Argon2id добавляются осознанно; соблюдай порядок
   согласования из workflow перед началом реализации.
3. Перенеси каркас в целевую структуру, обнови путь сборки Docker.
   Комментарий: main отвечает за запуск, app — за сборку, delivery — за HTTP.
   Сначала проверь сохранение существующего поведения без новой регистрации.
4. Добавь проверяемую env-конфигурацию и PostgreSQL pool.
   Комментарий: сервис должен сразу обнаруживать неправильные настройки,
   ограничивать время подключения и освобождать ресурсы при остановке.
5. Создай миграцию accounts и команду её применения.
   Комментарий: уникальность email обеспечивает сама БД, включая одновременные
   запросы. Проверяй миграции только на выделенной тестовой базе.
6. Определи Account, доменные ошибки и интерфейсы use case.
   Комментарий: бизнес-операция не должна зависеть от chi, SQL или библиотеки
   хеширования; password_hash не должен попадать в публичную модель ответа.
7. Реализуй Argon2id adapter с ограничением параллельных вычислений.
   Комментарий: соль защищает одинаковые пароли, а лимит вычислений ограничивает
   потребление памяти. Проверь параметры, формат хеша и отмену ожидания слота.
8. Реализуй PostgreSQL repository с параметризованным INSERT.
   Комментарий: только конфликт уникальности email означает account_exists;
   сетевые, SQL и остальные ошибки нельзя выдавать за дубликат аккаунта.
9. Реализуй Register use case по контракту ниже.
   Комментарий: валидируй вход, хешируй пароль, создай аккаунт и сохрани его.
   Не добавляй выдачу токенов, роли или автоматическую верификацию email.
10. Добавь HTTP handler, DTO, ограничения тела и отображение ошибок.
    Комментарий: handler переводит HTTP в вызов use case и обратно; клиент
    получает стабильные коды без внутренних ошибок и секретов.
11. Обнови readiness для проверки БД, сохрани отдельную liveness.
    Комментарий: живой процесс может временно не быть готов обслуживать запросы;
    это разные сигналы для инфраструктуры.
12. Добавь unit и PostgreSQL integration tests по критериям ниже.
    Комментарий: особенно проверь конкурентные дубликаты, границы валидации,
    ошибки repository и лимит hashing; пропуск DB-тестов не доказывает их успех.
13. Обнови OpenAPI, README и записи `.ai`.
    Комментарий: документы должны описывать реализованный контракт и оставшиеся
    ограничения, включая раскрытие существования email и отсутствие rate limit.
14. Выполни проверки и представь результат для ревью Codex.
    Комментарий: приложи фактические результаты build, tests, vet, lint, Docker
    и benchmark; отдельно обозначь то, что не удалось проверить. Публикацию
    выполняй только по отдельно установленным пользователем инструкциям.

## Observed starting point
services/auth has cmd/auth/main.go, internal/http/handlers.go and tests,
health/readiness endpoints, chi middleware and graceful shutdown. No account
storage, password hashing or authentication endpoints exist. go.mod declares
Go 1.26.2; verify installed/CI toolchain rather than changing it speculatively.
Docker builds ./cmd/auth and CI uses the service module.

## Outcome and boundaries
Implement one end-to-end operation: persist a registered account with a secure
password hash in PostgreSQL. Restructure the existing skeleton into the target
layers without losing current behavior. Registration does not log a user in,
issue tokens, verify email or grant roles. No login, sessions, refresh, Access,
Gateway, Redis, messaging, MFA, OAuth/OIDC or Kubernetes changes in this task.
This custom registration API must not be described as an OAuth/OIDC provider.

## Files and dependencies
Target locations:
- cmd/api/main.go: thin signal-aware entrypoint; replace cmd/auth, update Docker.
- cmd/migrate/main.go: version and up commands only for this step.
- internal/app/{app.go,wiring.go}: construct dependencies, own cleanup.
- internal/domain/{account.go,errors.go}: account and typed errors.
- internal/usecase/{register.go,ports.go}: registration, consumer-owned interfaces.
- internal/delivery/http/: router, DTO, registration handler, error mapping and
  middleware; relocate existing health behavior and tests.
- internal/repository/postgres/account.go: SQL implementation.
- internal/platform/{config,postgres,password}/: validated env config, pool,
  Argon2id implementation.
- migrations/000001_accounts.{up,down}.sql; api/openapi.yaml.
- README, Dockerfile and .ai documentation as required.

Before adding dependencies, Gemini writes a short ADR and decisions index entry
for pgx/v5, golang-migrate/v4 and golang.org/x/crypto/argon2. Use compatible pinned
versions, not automatic latest upgrades. chi is already approved. UUIDs may be
generated with crypto/rand and standard-library formatting; no extra dependency
is necessary. Tests use fakes where appropriate and real PostgreSQL for SQL.

## HTTP contract
POST /v1/auth/register; application/json; public endpoint, no access JWT.
Maximum request body: 4 KiB. Reject unknown JSON fields and trailing JSON values.
Input is exactly email and password; no caller-supplied ID, role or status.

Request example:
{"email":"person@example.com","password":"a-long-example-password"}

201 response (no Location header for a nonexistent GET endpoint):
{"account":{"id":"<uuid>","email":"person@example.com","status":"active","email_verified":false,"created_at":"<UTC RFC3339>"}}

Errors have one shape:
{"error":{"code":"invalid_request","message":"Invalid request","request_id":"<id>"}}

| HTTP | code | When |
| --- | --- | --- |
| 400 | invalid_request | Invalid JSON, email or password |
| 409 | account_exists | Canonical email is already registered |
| 413 | request_too_large | Body exceeds limit |
| 415 | unsupported_media_type | Content type is not application/json |
| 503 | service_unavailable | Known database availability/timeout failure |
| 500 | internal_error | Unexpected failure |

Do not send SQL, hashes or raw internal errors to clients. Success never returns
a password/hash/token. Duplicate registration explicitly exposes account
existence: this is an initial product tradeoff, not an enumeration-safe claim.
Do not publicly deploy registration before distributed abuse controls are added.

## Input and account rules
- Email: trim outer whitespace, require a bare address (no display name), ASCII
  only in this first contract, maximum 254 bytes. Lowercase the entire address
  as the explicit product identity policy; do not apply provider-specific rules
  such as removing dots or plus suffixes. Persist the canonical value.
- Password: valid UTF-8, 8-128 Unicode code points, at most 512 bytes; preserve
  exact contents, no trimming/normalization or composition requirements.
- Account ID: server-generated random UUID v4. Timestamps: UTC.
- New account: active, email_verified=false. Active means not administratively
  blocked; it does not imply verified identity or permission to any business data.
- Role/permission assignment belongs to Access and is absent here.

## Data model
accounts:
- id uuid PRIMARY KEY
- email text NOT NULL UNIQUE (canonical lowercase email)
- password_hash text NOT NULL
- status text NOT NULL CHECK (status IN ('active','disabled'))
- email_verified boolean NOT NULL DEFAULT false
- created_at timestamptz NOT NULL
- updated_at timestamptz NOT NULL

Atomic INSERT and database uniqueness are authoritative. Map only the relevant
email uniqueness violation to account_exists; do not map all SQL errors to 409.
Never rely on a pre-insert lookup to prevent concurrent duplicates.
Domain/response models must not accidentally serialize password hashes.

## Interfaces and operation flow
Use context.Context as the first argument for I/O methods.
Usecase ports: AccountRepository.Create(ctx, account) and PasswordHasher.Hash
(ctx, password). Constructors inject repository, hasher, ID generator and clock
as useful for deterministic tests; no global pool/config.
Flow: validate -> hash -> construct account -> INSERT -> return safe result.
Domain has no imports of chi, pgx, HTTP DTOs or Argon2 implementation.

## Password adapter
Use Argon2id with a random 16-byte salt and 32-byte output. Initial parameters:
memory=65536 KiB, iterations=3, parallelism=1; benchmark and record latency on
the actual environment. Store a versioned PHC-format string containing parameters
and salt. Do not invent a new cryptographic algorithm.
Bound concurrent hash computations (initial maximum 2 per replica, configurable).
Waiting for a slot respects request cancellation; do not spawn unbounded hashing
goroutines. Argon2 itself is not cancellable mid-computation; release capacity
only when computation finishes. Do not claim full hashing cancellation.

## Configuration and lifecycle
HTTP_ADDR default :8080; DATABASE_URL required; DB_CONNECT_TIMEOUT default 5s;
DB_QUERY_TIMEOUT default 3s; PASSWORD_HASH_CONCURRENCY default 2, positive and
bounded by validated configuration. Never print DSNs containing credentials.
Validate config before serving. Startup pool connection/Ping must be bounded.
/healthz reports process liveness; /readyz performs a short bounded DB check and
returns 503 when DB is unavailable. Preserve request ID, JSON logs, panic recovery,
HTTP timeouts and graceful shutdown. Stop HTTP before closing the pool.
Keep current health JSON where compatible; update readiness failure contract.
Metrics remain planned; do not invent a telemetry subsystem in this task.

## Threat model (STRIDE)
Assets: password plaintext, stored hashes, account identity and DB credentials.
Trust boundaries: untrusted client -> HTTP/usecase; service -> PostgreSQL.
Attackers: unauthenticated clients, concurrent/automated callers, DB readers.

| Category | Threat | Mitigation / residual risk |
| --- | --- | --- |
| Spoofing | Caller supplies admin role or verified status | Reject unknown fields; server controls account state |
| Tampering | SQL injection, duplicate identity races | Parameterized SQL, canonical email, UNIQUE constraint |
| Repudiation | Untraceable failed requests | Request IDs and safe structured logs; durable audit is later |
| Disclosure | Password/hash in responses or logs; email probing | Safe DTOs, redacted logs; 409 enumeration remains documented |
| Denial of service | Huge bodies and expensive hashes | Body/password limits, bounded hashing, timeouts; distributed limits still required |
| Elevation | Registration grants privileges | No roles, no tokens, no business permissions |

Follow OWASP ASVS authentication, input-validation and credential-storage
principles. This is not a claim of complete ASVS compliance.

## Acceptance criteria and evidence
1. Valid registration returns 201 and stores exactly one canonical account with
   a PHC Argon2id hash; different registrations use different salts.
2. Invalid inputs/unknown fields/trailing values/content types/oversized bodies
   have documented statuses and no inserted account.
3. Concurrent registrations for equivalent emails produce one account, one 201
   and 409 for duplicates, proved against PostgreSQL.
4. Repository errors map correctly; internal error details and credentials never
   appear in responses/logs. Fakes test unexpected and unavailable failures.
5. Cancelled requests do not wait indefinitely for hashing slots or DB calls.
   Tests cover the configured hashing concurrency bound without timing-only assertions.
6. Database loss makes readiness fail while liveness remains healthy.
7. Migrations apply to a fresh test DB; rollback is tested only on a disposable DB.
8. Existing operational behavior remains covered; Docker builds the new cmd/api.
9. OpenAPI matches implemented requests, responses and status codes.
10. Run go build ./..., go test -race ./..., go vet ./..., golangci-lint run and
    Docker build. Integration tests must run with a disposable PostgreSQL database;
    skipped DB tests are not passing DB evidence. Record Argon2 benchmark results.

Known tooling concern: CI currently pins golangci-lint v1.64.6 with a Go 1.26.2
module. Check compatibility; report evidence and update tooling only if required
to validate this change. Do not bypass checks or silently downgrade Go.

## Gemini handoff and review
Before implementation, state a short plan and dependency ADRs according to
.ai/workflow.md. Limit changes to AUTH-01; keep Access/Gateway as documentation.
Return changed files, API/schema evidence, executed checks, benchmark, failures
and residual risks. Codex reviews layer boundaries, concurrency, SQL error
mapping, password handling and contract correctness before the next task.
This brief itself authorizes no commit, push, deployment or automatic Gemini run;
delivery instructions are to be settled with the user for the implementation.
Next proposed task: login + signing/JWKS and session design, followed by refresh
rotation/logout. Specify complete token/session contracts before writing them.
