-- ============================================================
-- BookIt v4 Migration – run against an existing database
-- mariadb -u root -p booking < migrate_v4.sql
-- ============================================================
USE booking;

-- ── Per-user timezone preference ────────────────────────────
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS timezone VARCHAR(100) NOT NULL DEFAULT 'UTC';
