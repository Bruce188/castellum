-- V12: Add failure_reason column to scan table.
-- Nullable: success-path rows never populate it.
-- Existing rows get NULL automatically.
ALTER TABLE scan ADD COLUMN failure_reason TEXT NULL;
