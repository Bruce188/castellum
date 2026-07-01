-- V33: durable NVD full-backfill resume cursor (singleton row id=1).
--
-- window_end holds the publish-date upper bound of the last successfully-committed
-- FULL_BACKFILL window. NvdSyncService.fullBackfillPull() reads it at start and resumes
-- there instead of the configured start year, so an interrupted multi-hour historical
-- backfill restarts where it stopped rather than re-pulling from the start year. NULL means
-- no backfill is in progress: a fresh backfill starts at castellum.nvd.backfill-start-year
-- and clears the cursor again on completion. Mirrors the per-chunk resume progress that
-- ScanExecutionService persists on the scan row.
--
-- Purely additive: no ALTER/DROP of any existing table.

CREATE TABLE nvd_backfill_cursor (
    id          BIGINT PRIMARY KEY,
    window_end  TIMESTAMPTZ
);

-- Seed the singleton row (id=1) with no cursor — a fresh backfill starts at the start year.
INSERT INTO nvd_backfill_cursor (id, window_end) VALUES (1, NULL);
