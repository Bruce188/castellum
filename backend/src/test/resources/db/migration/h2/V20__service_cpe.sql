-- H2-compatible version of V20__service_cpe.sql for Flyway integration tests.
ALTER TABLE service ADD COLUMN cpe VARCHAR(255);
