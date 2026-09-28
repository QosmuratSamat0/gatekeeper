# 0002: Use chi router

## Status
Accepted

## Context
The auth service requires route groups with different middleware chains (e.g., public endpoints, authenticated routes, rate-limited handlers). While the standard library's `net/http.ServeMux` supports HTTP methods and path parameters, it does not support route grouping or clean middleware chaining out of the box.

## Decision
Use `github.com/go-chi/chi/v5` as the HTTP router. It is built directly on top of `net/http`, introduces zero external transitive dependencies, and handlers remain standard `http.Handler` implementations.

## Consequences
+ Clean middleware composition and route grouping.
+ Easy to migrate and test because handlers remain standard `http.Handler`.
- Introduces one external dependency to maintain and update.
