-- ============================================================
-- BookIt v5 Migration – run against an existing database
-- mariadb -u root -p booking < migrate_v5.sql
-- ============================================================
USE booking;

-- ── IP address tracking in activity log ─────────────────────
ALTER TABLE activity_log
  ADD COLUMN IF NOT EXISTS ip_address VARCHAR(45) DEFAULT NULL;
