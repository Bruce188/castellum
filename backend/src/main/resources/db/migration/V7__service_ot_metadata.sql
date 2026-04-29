ALTER TABLE service ADD COLUMN vendor TEXT;
ALTER TABLE service ADD COLUMN product TEXT;
ALTER TABLE service ADD COLUMN protocol_family TEXT;
CREATE INDEX service_protocol_family_idx ON service (protocol_family) WHERE protocol_family IS NOT NULL;
