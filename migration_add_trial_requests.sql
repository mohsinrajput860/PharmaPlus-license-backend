-- ============================================================
-- Migration: Add owner_name + city columns to trial_requests
-- Run this if your database was created before these columns existed
--
-- Command:
--   wrangler d1 execute pharma-license-db --remote --command="ALTER TABLE trial_requests ADD COLUMN owner_name TEXT DEFAULT ''"
--   wrangler d1 execute pharma-license-db --remote --command="ALTER TABLE trial_requests ADD COLUMN city TEXT DEFAULT ''"
--
-- OR run this full migration file:
--   wrangler d1 execute pharma-license-db --remote --file=./migration_add_trial_requests.sql
-- ============================================================

-- Add missing columns (safe — will error only if columns already exist, which is fine)
ALTER TABLE trial_requests ADD COLUMN owner_name TEXT DEFAULT '';
ALTER TABLE trial_requests ADD COLUMN city TEXT DEFAULT '';

-- Recreate table fresh if it doesn't exist at all (safe with IF NOT EXISTS)
CREATE TABLE IF NOT EXISTS trial_requests (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  hwid        TEXT NOT NULL,
  phone       TEXT NOT NULL,
  shop_name   TEXT DEFAULT '',
  owner_name  TEXT DEFAULT '',
  city        TEXT DEFAULT '',
  app_version TEXT DEFAULT '',
  status      TEXT NOT NULL DEFAULT 'pending',
  created_at  INTEGER NOT NULL DEFAULT (unixepoch() * 1000),
  resolved_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_trial_requests_status ON trial_requests (status);
CREATE INDEX IF NOT EXISTS idx_trial_requests_hwid   ON trial_requests (hwid);
