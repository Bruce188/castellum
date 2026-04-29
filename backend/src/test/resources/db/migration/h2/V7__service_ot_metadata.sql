-- H2-compatible version of V7__service_ot_metadata.sql for Flyway integration tests.
ALTER TABLE service ADD COLUMN vendor TEXT;
ALTER TABLE service ADD COLUMN product TEXT;
ALTER TABLE service ADD COLUMN protocol_family TEXT;
CREATE INDEX service_protocol_family_idx ON service (protocol_family);
