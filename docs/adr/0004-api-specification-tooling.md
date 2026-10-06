# ADR 0004: API Specification Tooling and Swagger 2.0 Generation

## Status
Accepted

## Context
API documentation must accurately represent implemented HTTP endpoints, DTOs, validation bounds, and error shapes without diverging from source code. The user requested code-first generation via `swaggo/swag`.

We investigated `swaggo/swag` version compatibility:
The installed CLI toolchain is `swaggo/swag v1.16.4`. Swag v1 exclusively generates **Swagger 2.0** (`swagger.yaml` / `swagger.json`). It does not natively produce OpenAPI 3.0.3 documents. Mislabeling Swagger 2.0 as OpenAPI 3.0.3 is invalid and breaks tooling.

## Decision
1. Use `github.com/swaggo/swag v1.16.4` for code-first generation from handler and DTO declarative annotations.
2. Annotate `cmd/api/main.go`, `Register` handler, `Healthz`, `Readyz`, and request/response DTOs with standard Swag doc comments.
3. Generate Swagger 2.0 artifacts into `services/auth/api/` (`docs.go`, `swagger.yaml`, `swagger.json`) using:
   ```bash
   swag init -g cmd/api/main.go -d ./ --parseInternal -o ./api
   ```
4. Serve the interactive documentation interface using the ready-made open-source middleware `github.com/swaggo/http-swagger/v2` mounted at `/swagger/*` with permanent redirect from `/swagger`.
5. Strictly avoid writing custom documentation HTML pages or templates; all Swagger UI assets and scripts are served directly from the ready-made library.
6. Establish Go code and Swag annotations as the single source of truth for API contracts. Remove hand-crafted duplicate OpenAPI specifications to eliminate contract split.
7. Enforce specification freshness in CI by running `swag init` and asserting `git diff --exit-code api/`.

## Consequences
- (+) Single source of truth: handlers, DTO structs, field tags (format, min/max length, required), and error schemas define the contract directly.
- (+) Automated drift detection: CI rejects pull requests where code changes are made without regenerating API documentation.
- (+) Ready-made interactive UI: developer documentation is accessible at `/swagger/index.html` out-of-the-box without maintaining custom HTML/CSS/JS files.
- (+) Generated files (`api/docs.go`, `api/swagger.yaml`, `api/swagger.json`) are completely reproducible via standard CLI tooling.
