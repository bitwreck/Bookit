-- ============================================================
-- BookIt v8 Migration – run against an existing database
-- mariadb -u root -p booking < migrate_v8.sql
-- ============================================================
USE booking;

INSERT IGNORE INTO settings (`key`, `value`) VALUES
  ('purge_enabled',        'false'),
  ('purge_retention_value','12'),
  ('purge_retention_unit', 'months'),
  ('purge_schedule_value', '1'),
  ('purge_schedule_unit',  'months'),
  ('purge_last_run',       '');
