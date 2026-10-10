-- 000004_sessions_keyset_index.down.sql
-- Drop composite partial index for keyset pagination

DROP INDEX IF EXISTS idx_sessions_account_active_keyset;
