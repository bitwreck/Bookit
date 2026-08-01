-- migrate_v11.sql – Add password_hash to local user accounts
USE booking;
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash VARCHAR(255) NULL AFTER auth_source;
