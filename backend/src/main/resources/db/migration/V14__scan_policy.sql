-- V14: scheduled scan policies + scan.retry_count column.
--
-- scan_policy stores cron-driven scan templates managed by ADMIN through
-- /api/scan-policy. A separate poller bean (ScanPolicyScheduler) wakes every
-- 60s and submits scans for policies whose CronExpression.next(...) has
-- elapsed since last_triggered_at.
--
-- scan.retry_count tracks the auto-retry attempt counter for "nmap timed out"
-- failures (cap = 2). Defaulting to 0 so existing rows backfill cleanly.

CREATE TABLE scan_policy (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    cron_expression TEXT NOT NULL,
    cidr TEXT NOT NULL,
    scan_type TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_triggered_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_scan_policy_enabled
    ON scan_policy (enabled);

ALTER TABLE scan ADD COLUMN retry_count INTEGER NOT NULL DEFAULT 0;
