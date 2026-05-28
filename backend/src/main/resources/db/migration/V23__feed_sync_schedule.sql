-- V23: durable singleton feed-sync schedule row.
--
-- feed_sync_schedule stores the scheduled auto-pull's runtime config, last-run
-- metadata, and retry state. Exactly one row (id=1) is seeded here; the
-- FeedSyncScheduler re-reads it every tick and writes outcomes back — making the
-- schedule restart-safe and database-authoritative.
--
-- Purely additive: no ALTER/DROP of any existing table.

CREATE TABLE feed_sync_schedule (
    id                   BIGINT PRIMARY KEY,
    enabled              BOOLEAN NOT NULL DEFAULT TRUE,
    cron_expression      TEXT NOT NULL,
    last_run_at          TIMESTAMPTZ,
    last_status          TEXT,
    last_error           TEXT,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    retry_after_at       TIMESTAMPTZ,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ
);

-- Seed the singleton row (id=1). Enabled by default; uses the same cron that
-- the legacy @Scheduled annotation used as its fallback default.
INSERT INTO feed_sync_schedule (id, enabled, cron_expression, consecutive_failures, created_at)
VALUES (1, TRUE, '0 0 6 * * *', 0, NOW());
