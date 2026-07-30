-- ============================================================
-- Booking Tool – MariaDB Schema
-- Run: mariadb -u root -p < schema.sql
-- ============================================================

CREATE DATABASE IF NOT EXISTS booking CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE booking;

-- ── Resources ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS resources (
  id          INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name        VARCHAR(255)  NOT NULL,
  description TEXT,
  color       VARCHAR(7)    NOT NULL DEFAULT '#64748b',
  created_at  TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
  updated_at  TIMESTAMP     DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── Registered users ───────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
  id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name       VARCHAR(255) NOT NULL,
  email      VARCHAR(255) NOT NULL,
  phone      VARCHAR(30)  DEFAULT NULL,
  timezone    VARCHAR(100)              NOT NULL DEFAULT 'UTC',
  auth_source ENUM('local','ldap')      NOT NULL DEFAULT 'local',
  created_at  TIMESTAMP                 DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP    DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uk_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── Appointments ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS appointments (
  id               INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  resource_id      INT UNSIGNED  NOT NULL,
  user_id          INT UNSIGNED  DEFAULT NULL,
  title            VARCHAR(255)  NOT NULL,
  description      TEXT,
  booked_by_name   VARCHAR(255)  NOT NULL,
  booked_by_email  VARCHAR(255)  NOT NULL,
  booked_by_phone  VARCHAR(30)   DEFAULT NULL,
  start_time       DATETIME      NOT NULL,
  end_time         DATETIME      NOT NULL,
  timezone         VARCHAR(100)  NOT NULL DEFAULT 'UTC',
  status           ENUM('confirmed','pending','cancelled') DEFAULT 'confirmed',
  created_at       TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
  updated_at       TIMESTAMP     DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  CONSTRAINT fk_appt_resource FOREIGN KEY (resource_id)
    REFERENCES resources(id) ON DELETE CASCADE,
  CONSTRAINT fk_appt_user FOREIGN KEY (user_id)
    REFERENCES users(id) ON DELETE SET NULL,
  INDEX idx_resource   (resource_id),
  INDEX idx_start_time (start_time),
  INDEX idx_status     (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

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

-- ── Activity log ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS activity_log (
  id                INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  action            ENUM('created','cancelled','deleted') NOT NULL,
  appointment_title VARCHAR(255)  NOT NULL,
  resource_name     VARCHAR(255)  NOT NULL,
  resource_color    VARCHAR(7)    NOT NULL DEFAULT '#64748b',
  actor             VARCHAR(255)  DEFAULT NULL,  -- email or 'admin'
  ip_address        VARCHAR(45)   DEFAULT NULL,
  created_at        TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── LDAP authentication log ────────────────────────────────
CREATE TABLE IF NOT EXISTS ldap_log (
  id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  event      ENUM('success','bind_failed','search_failed','user_not_found','auth_failed','error') NOT NULL,
  email      VARCHAR(255)  DEFAULT NULL,
  detail     TEXT          DEFAULT NULL,
  ip_address VARCHAR(45)   DEFAULT NULL,
  created_at TIMESTAMP     DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_ldap_log_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── App settings ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS settings (
  `key`   VARCHAR(100) PRIMARY KEY,
  `value` TEXT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT IGNORE INTO settings (`key`, `value`) VALUES
  ('require_cancel_code', 'true'),
  ('ldap_enabled',        'false'),
  ('ldap_url',            ''),
  ('ldap_base_dn',        ''),
  ('ldap_bind_dn',        ''),
  ('ldap_bind_pass',      ''),
  ('ldap_user_filter',    '(mail={{username}})'),
  ('ldap_name_attr',      'cn'),
  ('ldap_email_attr',     'mail'),
  ('ldap_phone_attr',     'telephoneNumber'),
  ('purge_enabled',       'false'),
  ('purge_retention_value','12'),
  ('purge_retention_unit','months'),
  ('purge_schedule_value','1'),
  ('purge_schedule_unit', 'months'),
  ('purge_last_run',      '');

-- ── Admin users ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS admins (
  id            INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  username      VARCHAR(100) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  created_at    TIMESTAMP    DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ── Seed: default admin  (password: Admin1234!)
-- Change this immediately after first login via the admin panel.
INSERT IGNORE INTO admins (username, password_hash) VALUES
  ('admin', '$2a$10$Z6fAlO4p8cHqHdfOCyQ1meJXJoauznKobIeIa63ENU7PUp1oNsBR.');

-- ── Seed: sample resources ─────────────────────────────────
INSERT IGNORE INTO resources (id, name, description, color) VALUES
  (1, 'Camera A',       'Sony FX3 cinema camera kit',         '#0ea5e9'),
  (2, 'Drone Kit',      'DJI Mavic 3 with spare batteries',   '#f59e0b'),
  (3, 'Production Van', '16-ft cargo van with lift gate',     '#10b981');
