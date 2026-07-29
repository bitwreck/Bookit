-- ============================================================
-- BookIt v3 Migration – run against an existing database
-- mariadb -u root -p booking < migrate_v3.sql
-- ============================================================
USE booking;

-- ── App settings ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS settings (
  `key`   VARCHAR(100) PRIMARY KEY,
  `value` TEXT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT IGNORE INTO settings (`key`, `value`) VALUES
  ('require_cancel_code', 'true');
