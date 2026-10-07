-- 000003_create_refresh_tokens.up.sql
-- Create refresh_tokens table for rotating refresh tokens and reuse detection

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id UUID PRIMARY KEY,
    session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ NULL,
    CONSTRAINT chk_refresh_tokens_expiry_order CHECK (expires_at > created_at),
    CONSTRAINT chk_refresh_tokens_consumed_order CHECK (consumed_at IS NULL OR consumed_at >= created_at)
);

-- Index to quickly locate all token family records for a session
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_session_id ON refresh_tokens (session_id);

-- Partial unique index guaranteeing strictly at most one active (unconsumed) token per session family
CREATE UNIQUE INDEX IF NOT EXISTS uq_refresh_tokens_active_session ON refresh_tokens (session_id) WHERE consumed_at IS NULL;
