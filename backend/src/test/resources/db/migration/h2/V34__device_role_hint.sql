-- V34 H2 mirror: device.role_hint column (DHCP/mDNS role hints).
-- Identical syntax to the Postgres migration — a plain nullable ADD COLUMN VARCHAR
-- is shared between H2 (PostgreSQL mode) and Postgres. Nullable, no default, no
-- CHECK (mirrors V26's device_role posture).
ALTER TABLE device ADD COLUMN role_hint VARCHAR(32);
