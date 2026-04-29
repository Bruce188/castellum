CREATE TABLE service (
  id BIGSERIAL PRIMARY KEY,
  device_id BIGINT NOT NULL REFERENCES device(id) ON DELETE CASCADE,
  port INT NOT NULL CHECK (port BETWEEN 1 AND 65535),
  protocol TEXT NOT NULL,
  name TEXT,
  version TEXT,
  observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT service_dev_port_proto_unique UNIQUE (device_id, port, protocol)
);
