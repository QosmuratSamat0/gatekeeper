# 0003: Auth persistence and password hashing

## Status
Accepted

## Context
Step AUTH-01 introduces persistent storage for user accounts and secure credential management for the Auth service. To ensure reliability, performance, and security according to the project rules:
1. PostgreSQL is the authoritative datastore for accounts. A native, robust connection pool and query interface is required.
2. Database schema evolution must be versioned, idempotent, and reversible.
3. Passwords must be hashed using a memory-hard, GPU-resistant algorithm (Argon2id) with unique random salts and safe parameters, stored in PHC format.
4. Account IDs must be unpredictable globally unique identifiers (UUID v4).

## Decision
1. Use `github.com/jackc/pgx/v5` and `pgxpool` as the PostgreSQL driver and connection pool. It provides native PostgreSQL protocol support, connection lifecycle control, and robust error classification.
2. Use `github.com/golang-migrate/migrate/v4` for managing database migrations via SQL files.
3. Use `golang.org/x/crypto/argon2` (Argon2id) for password hashing with a 16-byte random salt and 32-byte hash length, bounded by a concurrency semaphore.
4. Use standard library `crypto/rand` for generating UUID v4 identifiers, avoiding unnecessary third-party dependencies.

## Consequences
+ High performance and native PostgreSQL type handling with `pgx/v5`.
+ Strict, audited cryptography via official Go extended standard library (`x/crypto/argon2`).
+ Clean separation of migrations and zero external dependency for UUID generation.
- Introduces pinned dependencies (`pgx/v5`, `golang-migrate/v4`, `x/crypto`) that require dependency maintenance and security scanning.
