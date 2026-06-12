-- V31 H2 mirror: chunked wide-range scanning columns on scan.
-- Identical syntax to the Postgres migration — ADD COLUMN, INT, BOOLEAN DEFAULT and
-- CASE expressions are shared between H2 (PostgreSQL mode) and Postgres.
ALTER TABLE scan ADD COLUMN skip_host_discovery BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE scan ADD COLUMN chunks_total INT;
ALTER TABLE scan ADD COLUMN chunks_done INT;

-- Backfill pre-existing rows: every legacy scan ran as a single implicit chunk.
-- COMPLETE rows finished that chunk; every other status did not.
UPDATE scan SET chunks_total = 1;
UPDATE scan SET chunks_done = CASE WHEN status = 'COMPLETE' THEN 1 ELSE 0 END;
