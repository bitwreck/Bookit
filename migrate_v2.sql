-- ============================================================
-- BookIt v2 Migration – run against an existing database
-- mariadb -u root -p booking < migrate_v2.sql
-- ============================================================
USE booking;

-- ── Registered users ───────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
  id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name       VARCHAR(255) NOT NULL,
  email      VARCHAR(255) NOT NULL,
  phone      VARCHAR(30)  DEFAULT NULL,
  created_at TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP    DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uk_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── Add phone + user_id to appointments ────────────────────
ALTER TABLE appointments
  ADD COLUMN IF NOT EXISTS booked_by_phone VARCHAR(30) DEFAULT NULL
    AFTER booked_by_email,
  ADD COLUMN IF NOT EXISTS user_id INT UNSIGNED DEFAULT NULL
    AFTER resource_id;

-- Add FK separately (MariaDB doesn't support IF NOT EXISTS on constraints;
-- ignore the error if you run this script more than once)
ALTER TABLE appointments
  ADD CONSTRAINT fk_appt_user
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL;

-- ── Cancellation codes ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS cancellation_codes (
  id             INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  appointment_id INT UNSIGNED  NOT NULL,
  code_hash      VARCHAR(64)   NOT NULL,
  expires_at     DATETIME      NOT NULL,
  used           TINYINT(1)    DEFAULT 0,
  created_at     TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_cc_appt FOREIGN KEY (appointment_id)
    REFERENCES appointments(id) ON DELETE CASCADE,
  INDEX idx_cc_appt (appointment_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
