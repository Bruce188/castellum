-- V23 H2 mirror: durable feed-sync schedule (singleton row id=1).
-- Mirrors prod V23__feed_sync_schedule.sql for @DataJpaTest / Flyway integration
-- slices that run the H2 migration set with ddl-auto=validate.
-- H2 portability (per the V14 mirror convention): TIMESTAMPTZ -> TIMESTAMP,
-- NOW() -> CURRENT_TIMESTAMP, TEXT -> VARCHAR(255) (matches the entity's default
-- String -> VARCHAR mapping that Hibernate schema-validation checks against).

CREATE TABLE feed_sync_schedule (
    id BIGINT PRIMARY KEY,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    cron_expression VARCHAR(255) NOT NULL,
    last_run_at TIMESTAMP,
    last_status VARCHAR(255),
    last_error VARCHAR(255),
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    retry_after_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP
);

INSERT INTO feed_sync_schedule (id, enabled, cron_expression, consecutive_failures, created_at)
VALUES (1, TRUE, '0 0 6 * * *', 0, CURRENT_TIMESTAMP);
