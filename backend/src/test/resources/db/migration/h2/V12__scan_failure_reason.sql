-- V12 H2 mirror: Add failure_reason column to scan table.
-- H2 TEXT NULL is identical syntax to Postgres TEXT NULL.
ALTER TABLE scan ADD COLUMN failure_reason TEXT NULL;
