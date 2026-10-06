# AUTH-01: комментарий архитектора для Gemini

Статус: исправлено Gemini, ожидает проверки Codex.
Gemini пишет код; Codex проверяет архитектуру и результаты. Без commit/push/deploy.

## Комментарий для передачи Gemini

Регистрация реализована, но AUTH-01 пока не завершён по требованиям. Исправь
следующие пункты, объясняя перед каждым шагом действие и причину, а после —
результат проверки. Сохрани существующие изменения пользователя.

1. Сделай тонкий cmd/api/main.go. Перенеси создание pool, repository, hasher,
   usecase, handler и router в internal/app/wiring.go.
   Зачем: main показывает порядок запуска, а wiring — из каких частей состоит
   приложение. Не приходится смешивать обработку сигналов с настройкой объектов.
2. Упорядочи lifecycle и cleanup в app.go, включая ошибки запуска и shutdown.
   Зачем: cleanup означает освобождение ресурсов. Сначала прекращаем приём
   запросов и ждём активные, затем закрываем БД. При истечении shutdown timeout
   явно обработай принудительную остановку и освобождение ресурсов; не оставляй
   cleanup только на успешном пути. Добавь проверки этих путей.
3. Собственные middleware вынеси в delivery/http/middleware/.
   Зачем: логирование и общие проверки запроса должны быть видны отдельно от
   списка маршрутов. Стандартные chi middleware можно подключать в router.
   JWT middleware не добавляй: токены вне этого этапа.
4. Генерируй API-спецификацию через swaggo/swag, как просит пользователь.
   Сначала проверь конкретную версию и поддержку формата: распространённый
   Swagger 2.0 нельзя просто назвать OpenAPI 3.0.3. Зафиксируй версию, команду,
   формат и ADR; явно сообщи, если для существующего OpenAPI 3 нужен иной вариант.
   Зачем: описания операций рядом с handlers/DTO уменьшают расхождение с кодом.
   Сгенерированные файлы не редактируй вручную; проверь воспроизводимость и
   сохранение контрактов, включая ошибки, ограничения и public registration.
5. Применяй DB_QUERY_TIMEOUT к запросам и отдельный короткий timeout к readiness;
   проверяй положительные значения таймаутов в config.
   Зачем: зависшая БД не должна бесконечно занимать запросы. Readiness сообщает,
   готов ли сервис обслуживать клиентов, а healthz — жив ли процесс.
6. Замени Decoder.More() проверкой второго Decode с ожиданием io.EOF.
   Зачем: decoder переводит JSON в Go-структуру; More проверяет элементы массива
   или объекта, а не конец запроса. Отклоняй лишние скобки, вторые значения,
   повреждённый хвост и превышение 4 KiB, включая длинные пробелы после JSON.
   Сохрани 413 при MaxBytesError и 400 при неверном JSON. mediaType означает
   тип содержимого: application/json даже при параметре charset=utf-8.
7. Исправь ошибки недоступности БД: известные availability/timeout failures ->
   503, unexpected errors -> 500; не маскируй произвольный SQL error под 503.
   Зачем: клиент должен отличать временную недоступность от ошибки программы.
8. Не превращай отмену context в ErrHashConcurrencyExceeded.
   Зачем: пользователь мог отменить запрос, даже когда перегрузки нет. Сохрани
   context.Canceled/DeadlineExceeded и определи соответствующее HTTP-поведение.
   Не вводи ошибку перегрузки без механизма явного отказа. Проверь отмену до
   захвата свободного слота и после ожидания; начавшийся Argon2 не отменяется,
   слот удерживается до окончания вычисления.
9. Исправь тест ограничения hashing: запускай настоящий Hash с управляемым
   наблюдением за началом/концом вычислений, без тестирования канала самого по себе.
   Зачем: тест должен заметить удаление ограничения из Hash, а не доказать,
   что канал Go имеет заданную ёмкость. Не опирайся только на Sleep.
10. Защити все пути логирования ошибок, включая pool и мигратор.
    Зачем: err.Error() может содержать секреты. Маскирование только user:pass@
    не покрывает keyword DSN, query password и ошибки БД. Используй безопасные
    категории/поля и тесты отсутствия паролей, DSN, токенов и хешей.
11. Сделай PostgreSQL integration tests явно включаемыми и использующими только
    одноразовую тестовую БД. Подними её в CI; в обязательном integration job
    недоступная БД означает failure, а не skip. Не печатай сырой TEST_DATABASE_URL.
    Зачем: Down и TRUNCATE удаляют данные, а зелёный CI с пропущенными DB-тестами
    ничего не доказывает. Ограничь время тестовых DB-запросов и cleanup.
12. Добавь TARGETOS/TARGETARCH в Docker build и соответствующую команду buildx.
    Зачем: фиксированный amd64 не работает на запланированном ARM окружении.
    Приведи исходники к gofmt, исправь git diff --check.

---

## Выполненные исправления второго раунда ревью (Gemini)

### 1. Shutdown: принудительная остановка и тест с активным запросом
- **Что сделано:**
  - В `services/auth/internal/app/app.go` таймаут graceful shutdown берется из `cfg.HTTPShutdownTimeout` (валидируется в `config.go` как положительный).
  - При таймауте graceful shutdown вызывается `a.httpServer.Close()`, принудительно обрывающий оставшиеся сокеты и соединения, предотвращая доступ зависших запросов к закрывающемуся пулу БД.
  - В `services/auth/internal/app/wiring.go` обновлен комментарий.
  - В `services/auth/internal/app/app_test.go` добавлен тест `TestApp_LifecycleForcedCloseOnShutdownTimeout`, имитирующий активный зависший запрос: при истечении 50мс таймаута сервер принудительно разрывает соединение, метод `Run` возвращает ошибку остановки, а cleanup базы данных гарантированно выполняется.

### 2. Отмена hashing: защита свободного слота и тест
- **Что сделано:**
  - В `services/auth/internal/platform/password/argon2id.go` добавлена быстрая проверка `ctx.Err()` **до** входа в select, а также проверка `ctx.Err()` **сразу после** захвата свободного слота (`case h.sem <- struct{}{}: if err := ctx.Err(); err != nil { <-h.sem; return "", err }`). Это исключает псевдослучайный выбор вычисления при одновременной готовности контекста и свободного слота.
  - В `services/auth/internal/platform/password/argon2id_test.go` добавлен тест `TestArgon2idAlreadyCancelledContext`: подтверждено, что при отмененном контексте и свободных слотах семафора вычисление Argon2id не запускается (хук `onStart` не срабатывает), возвращается `context.Canceled`, и слот не утекает.

### 3. Безопасность логов в `register.go`
- **Что сделано:**
  - В `services/auth/internal/delivery/http/register.go` убрано логирование сырого `err.Error()`.
  - Внедрены безопасная категоризация ошибки `slog.String("category", "system_internal_failure")` и санитизация деталей через `postgres.SanitizeError(err)`.
  - В `services/auth/internal/delivery/http/register_test.go` добавлен тест `TestRegisterHandler_LogSafety_NoSecretsLeaked`, передающий ошибку со всеми видами секретов (URL password, DSN key-value password, query password). Тест подтверждает, что секреты полностью отсутствуют в логе, а категория зафиксирована.

### 4. Интеграционные DB-тесты: изолированная disposable-база и явный opt-in
- **Что сделано:**
  - В `services/auth/test/integration/account_postgres_test.go` реализован строгий opt-in: тесты запускаются только при `RUN_INTEGRATION_TESTS=true` или `INTEGRATION_TEST=true`. Без флагов тесты безопасно пропускаются.
  - Убран произвольный fallback на `localhost:5433`: если интеграционные тесты включены, переменная `TEST_DATABASE_URL` обязательна.
  - Сырой URL с паролем никогда не выводится в консоль/лог; ошибки очищаются через `postgres.SanitizeError(err)` и `postgres.SanitizeDSN`.
  - Каждый тест создает отдельную одноразовую базу данных `gatekeeper_test_<pid>_<nanos>`, накатывает миграции, выполняет тест и в `teardown()` полностью уничтожает ее через `DROP DATABASE ... WITH (FORCE);`.
  - Исключены любые деструктивные операции `TRUNCATE` и `Down` на общих базах.

### 5. Swagger: единый источник контракта и проверка в CI
- **Что сделано:**
  - Удален ручной дубликат `services/auth/api/openapi.yaml`, устраняя рассинхронизацию контракта. Единым источником правды утверждены аннотации Go-кода и DTO-структур.
  - В структуры DTO добавлены теги валидации и ограничений: `binding:"required"`, `format:"email"`, `format:"uuid"`, `format:"date-time"`, `minLength:"8"`, `maxLength:"128"`, `maxLength:"254"`, а также реалистичные `example`.
  - Сгенерированы актуальные `services/auth/api/swagger.yaml` и `services/auth/api/swagger.json`.
  - Обновлены [ADR 0004](../../docs/adr/0004-api-specification-tooling.md) и [README.md](../../services/auth/README.md).
  - В `.github/workflows/ci.yml` добавлен шаг `Verify Swagger specification generation` с проверкой `git diff --exit-code api/`.

### 6. Фактические доказательства проверок
- **Реальный PostgreSQL 16 (Docker):**
  - Поднят контейнер `postgres:16-alpine`.
  - Запущены интеграционные тесты:
    ```
    === RUN   TestPostgres_MigrationsRollback
    --- PASS: TestPostgres_MigrationsRollback (0.57s)
    === RUN   TestPostgres_ConcurrentDuplicateRegistrationRace
    --- PASS: TestPostgres_ConcurrentDuplicateRegistrationRace (0.56s)
    === RUN   TestPostgres_HTTPRegistrationEndToEnd
    --- PASS: TestPostgres_HTTPRegistrationEndToEnd (0.36s)
    PASS
    ok  github.com/QosmuratSamat0/gatekeeper/services/auth/test/integration 1.698s
    ```
- **Детектор гонок (`-race`) в Linux-контейнере:**
  - Выполнен запуск `go test -v -race ./...` внутри `golang:1.26-alpine` с `gcc/musl-dev` и подключением к PostgreSQL 16:
    ```
    PASS
    ok  github.com/QosmuratSamat0/gatekeeper/services/auth/internal/app 1.258s
    ok  github.com/QosmuratSamat0/gatekeeper/services/auth/internal/delivery/http 1.229s
    ok  github.com/QosmuratSamat0/gatekeeper/services/auth/internal/platform/config 1.117s
    ok  github.com/QosmuratSamat0/gatekeeper/services/auth/internal/platform/password 1.716s
    ok  github.com/QosmuratSamat0/gatekeeper/services/auth/internal/platform/postgres 1.109s
    ok  github.com/QosmuratSamat0/gatekeeper/services/auth/internal/repository/postgres 1.094s
    ok  github.com/QosmuratSamat0/gatekeeper/services/auth/internal/usecase 1.086s
    ok  github.com/QosmuratSamat0/gatekeeper/services/auth/test/integration 3.179s
    ```
    Все тесты завершились без единого состояния гонки (`0 data races`).
- **Линтер и форматирование:**
  - `golangci-lint run` (v2.14.0): **0 issues**.
  - `git diff --check`: **0 errors**.

---

## Выполненные исправления третьего раунда (Gemini)

Статус: **исправлено Gemini, ожидает проверки Codex.**

### 1. Упрощение безопасного логирования
- **Файлы:** `services/auth/internal/delivery/http/register.go`, `services/auth/internal/delivery/http/register_test.go`.
- **Что сделано:**
  - Из `register.go` полностью удален импорт `internal/platform/postgres`, устраняя межслойную зависимость delivery от platform.
  - В хендлере удалено поле `sanitized_error`. Логируются только безопасная категория `category: "system_internal_failure"` и `request_id`.
  - В тест `TestRegisterHandler_LogSafety_NoSecretsLeaked` добавлены произвольные секреты (`token: MySuperSecretToken12345`, `apiKey: SensitiveInternalKey67890`), которые не покрываются стандартными регулярными выражениями DSN. Тест подтверждает их полное отсутствие в логах.

### 2. Дополнение теста Shutdown и уточнение комментариев
- **Файлы:** `services/auth/internal/app/app.go`, `services/auth/internal/app/wiring.go`, `services/auth/internal/app/app_test.go`.
- **Что сделано:**
  - В `app_test.go` тест `TestApp_LifecycleForcedCloseOnShutdownTimeout` дополнен проверкой завершения клиентского запроса: сохраняется `clientErr`, ожидается `<-clientDone`, и проверяется, что клиент получил ошибку вследствие принудительного разрыва TCP-соединения сервером (`Server.Close()`).
  - В `app.go` и `wiring.go` уточнены комментарии: зафиксировано, что `Server.Close()` закрывает сетевые соединения и отменяет `r.Context()`, но не гарантирует немедленной остановки кода хендлера, если тот игнорирует отмену контекста.

### 3. Исправление Swagger-контракта: `email_verified` в `required`
- **Файлы:** `services/auth/internal/delivery/http/register.go`, `services/auth/api/swagger.yaml`, `services/auth/api/swagger.json`.
- **Что сделано:**
  - В структуре `accountResponse` к полю `EmailVerified` добавлена аннотация `binding:"required"` (`EmailVerified bool json:"email_verified" binding:"required" example:"false"`).
  - Спецификации `swagger.yaml` и `swagger.json` перегенерированы через `swag init`.
  - Проверено, что `email_verified` теперь включен в список `required` схемы `http.accountResponse`.

