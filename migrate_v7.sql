-- ============================================================
-- BookIt v7 Migration – run against an existing database
-- mariadb -u root -p booking < migrate_v7.sql
-- ============================================================
USE booking;

-- ── LDAP authentication log ─────────────────────────────────
CREATE TABLE IF NOT EXISTS ldap_log (
  id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  event      ENUM('success','bind_failed','search_failed','user_not_found','auth_failed','error') NOT NULL,
  email      VARCHAR(255)  DEFAULT NULL,
  detail     TEXT          DEFAULT NULL,
  ip_address VARCHAR(45)   DEFAULT NULL,
  created_at TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_ldap_log_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
