-- H2-compatible version of V22__device_os_columns.sql for Flyway integration tests.
-- Mirrors the prod device OS-fingerprint columns so @DataJpaTest slices that run
-- the H2 migration set with ddl-auto=validate see os_name/os_accuracy/os_cpe.
ALTER TABLE device ADD COLUMN os_name VARCHAR(255);
ALTER TABLE device ADD COLUMN os_accuracy INTEGER;
ALTER TABLE device ADD COLUMN os_cpe VARCHAR(255);
