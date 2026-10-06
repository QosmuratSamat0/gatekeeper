-- 000001_accounts.up.sql
-- Create accounts table for Gatekeeper Auth service

CREATE TABLE IF NOT EXISTS accounts (
    id UUID PRIMARY KEY,
    email TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
    email_verified BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT accounts_email_unique UNIQUE (email)
);
