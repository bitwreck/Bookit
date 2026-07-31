-- ============================================================
-- Migration v10 – HTTPS redirect setting
-- Run against an existing database BEFORE restarting the app.
-- ============================================================
USE booking;

INSERT IGNORE INTO settings (`key`, `value`) VALUES ('https_redirect', 'true');
