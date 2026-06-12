-- V31: chunked wide-range scanning columns on scan.
--
-- skip_host_discovery: operator flag — SERVICE_DETECT scans the whole CIDR with -Pn
--   instead of consulting the alive-host inventory. NOT NULL DEFAULT FALSE so legacy
--   rows and two-field submissions behave exactly as before.
-- chunks_total / chunks_done: chunk-progress counters, seeded at the RUNNING
--   transition and incremented per finished /22 chunk. Nullable — a fresh PENDING
--   row has no chunk plan yet.
ALTER TABLE scan ADD COLUMN skip_host_discovery BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE scan ADD COLUMN chunks_total INT;
ALTER TABLE scan ADD COLUMN chunks_done INT;

-- Backfill pre-existing rows: every legacy scan ran as a single implicit chunk.
-- COMPLETE rows finished that chunk; every other status did not.
UPDATE scan SET chunks_total = 1;
UPDATE scan SET chunks_done = CASE WHEN status = 'COMPLETE' THEN 1 ELSE 0 END;
