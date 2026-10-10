-- 000006_create_password_reset_tokens.up.sql
-- Table to store single-use password reset token hashes bounded to at most one record per account.

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    account_id  UUID PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    token_hash  BYTEA NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    created_at  TIMESTAMPTZ NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL
);
