CREATE TABLE device (
  id BIGSERIAL PRIMARY KEY,
  ip_address TEXT NOT NULL,
  hostname TEXT,
  mac_address TEXT,
  first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT device_ip_unique UNIQUE (ip_address)
);
