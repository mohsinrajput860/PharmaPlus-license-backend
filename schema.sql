-- ============================================================
-- PharmaPlus License Management — D1 SQLite Schema
-- Run: wrangler d1 execute pharma-license-db --remote --file=./schema.sql
-- ============================================================

-- Registered machines / stores
CREATE TABLE IF NOT EXISTS machines (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  hwid            TEXT    NOT NULL UNIQUE,
  shop_name       TEXT    NOT NULL DEFAULT 'Unknown Store',
  owner_name      TEXT    NOT NULL DEFAULT '',
  phone           TEXT    NOT NULL DEFAULT '',
  city            TEXT    NOT NULL DEFAULT '',
  status          TEXT    NOT NULL DEFAULT 'inactive',   -- active | inactive | revoked | trial
  license_expiry  INTEGER,                               -- Unix ms, NULL = permanent
  is_permanent    INTEGER NOT NULL DEFAULT 0,            -- 1 = permanent license
  created_at      INTEGER NOT NULL DEFAULT (unixepoch() * 1000),
  last_seen       INTEGER,
  app_version     TEXT    DEFAULT '',
  open_count      INTEGER NOT NULL DEFAULT 0,
  notes           TEXT    DEFAULT ''
);

-- Feature flags per machine
CREATE TABLE IF NOT EXISTS machine_features (
  id                INTEGER PRIMARY KEY AUTOINCREMENT,
  hwid              TEXT    NOT NULL UNIQUE,
  mobile_app        INTEGER NOT NULL DEFAULT 1,   -- 1=enabled, 0=disabled
  cloud_backup      INTEGER NOT NULL DEFAULT 1,
  reports           INTEGER NOT NULL DEFAULT 1,
  purchases         INTEGER NOT NULL DEFAULT 1,
  expenses          INTEGER NOT NULL DEFAULT 1,
  returns_module    INTEGER NOT NULL DEFAULT 1,
  suppliers         INTEGER NOT NULL DEFAULT 1,
  multi_user        INTEGER NOT NULL DEFAULT 1,
  lan_sync          INTEGER NOT NULL DEFAULT 1,
  FOREIGN KEY (hwid) REFERENCES machines(hwid) ON DELETE CASCADE
);

-- License activity log
CREATE TABLE IF NOT EXISTS license_logs (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  hwid        TEXT    NOT NULL,
  action      TEXT    NOT NULL,   -- authorized | revoked | extended | trial | feature_updated
  detail      TEXT    DEFAULT '',
  performed_by TEXT   DEFAULT 'admin',
  created_at  INTEGER NOT NULL DEFAULT (unixepoch() * 1000)
);

-- Admin sessions (JWT token revocation support)
CREATE TABLE IF NOT EXISTS admin_sessions (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  token_hash  TEXT    NOT NULL UNIQUE,
  created_at  INTEGER NOT NULL DEFAULT (unixepoch() * 1000),
  expires_at  INTEGER NOT NULL,
  revoked     INTEGER NOT NULL DEFAULT 0
);

-- ─── Indexes ─────────────────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_machines_hwid    ON machines (hwid);
CREATE INDEX IF NOT EXISTS idx_machines_status  ON machines (status);
CREATE INDEX IF NOT EXISTS idx_logs_hwid        ON license_logs (hwid);
CREATE INDEX IF NOT EXISTS idx_logs_created     ON license_logs (created_at DESC);
