-- V33 H2 mirror: durable NVD full-backfill resume cursor (singleton row id=1).
-- Mirrors prod V33__nvd_backfill_cursor.sql for @DataJpaTest / Flyway integration slices
-- that run the H2 migration set with ddl-auto=validate.
-- H2 portability (per the V23 mirror convention): TIMESTAMPTZ -> TIMESTAMP.

CREATE TABLE nvd_backfill_cursor (
    id          BIGINT PRIMARY KEY,
    window_end  TIMESTAMP
);

INSERT INTO nvd_backfill_cursor (id, window_end) VALUES (1, NULL);
