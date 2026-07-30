-- ============================================================
-- Migration v9 – Resource Categories
-- Run against an existing database BEFORE restarting the app.
-- ============================================================
USE booking;

-- 1. Create categories table
CREATE TABLE IF NOT EXISTS categories (
  id         INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  name       VARCHAR(255) NOT NULL,
  created_at TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP    DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uk_category_name (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 2. Seed a default category so existing resources have somewhere to go
INSERT IGNORE INTO categories (id, name) VALUES (1, 'General');

-- 3. Add category_id to resources (nullable first so existing rows don't fail)
ALTER TABLE resources
  ADD COLUMN IF NOT EXISTS category_id INT UNSIGNED NULL
    AFTER id;

-- 4. Assign all existing resources to the default category
UPDATE resources SET category_id = 1 WHERE category_id IS NULL;

-- 5. Make category_id NOT NULL and add FK + index
ALTER TABLE resources
  MODIFY COLUMN category_id INT UNSIGNED NOT NULL,
  ADD CONSTRAINT fk_resource_category
    FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE RESTRICT,
  ADD INDEX idx_resource_category (category_id);
