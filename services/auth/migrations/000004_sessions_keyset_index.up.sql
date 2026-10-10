-- 000004_sessions_keyset_index.up.sql
-- Composite partial index for keyset pagination of active account sessions

CREATE INDEX IF NOT EXISTS idx_sessions_account_active_keyset
ON sessions (account_id, created_at DESC, id DESC)
WHERE revoked_at IS NULL;
