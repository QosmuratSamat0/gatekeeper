-- 000005_create_email_verification_tokens.up.sql
-- Table to store single-use email verification token hashes bounded to at most one record per account.

CREATE TABLE IF NOT EXISTS email_verification_tokens (
    account_id  UUID PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    token_hash  BYTEA NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    created_at  TIMESTAMPTZ NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL
);
