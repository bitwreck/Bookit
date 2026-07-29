-- ============================================================
-- BookIt v6 Migration – run against an existing database
-- mariadb -u root -p booking < migrate_v6.sql
-- ============================================================
USE booking;

-- ── Auth source on users (local vs ldap) ────────────────────
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS auth_source ENUM('local','ldap') NOT NULL DEFAULT 'local';

-- ── LDAP configuration in settings ──────────────────────────
INSERT IGNORE INTO settings (`key`, `value`) VALUES
  ('ldap_enabled',     'false'),
  ('ldap_url',         ''),
  ('ldap_base_dn',     ''),
  ('ldap_bind_dn',     ''),
  ('ldap_bind_pass',   ''),
  ('ldap_user_filter', '(mail={{username}})'),
  ('ldap_name_attr',   'cn'),
  ('ldap_email_attr',  'mail'),
  ('ldap_phone_attr',  'telephoneNumber');
