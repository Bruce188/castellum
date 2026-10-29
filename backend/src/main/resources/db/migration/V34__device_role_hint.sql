-- V34: device.role_hint column — persisted DHCP/mDNS role-hint evidence.
--
-- role_hint: nullable STRING-mapped enum (RoleHint), highest-rank hint ever observed
--   for the device. Most devices never get a hint, so the column stays NULL. No default,
--   no CHECK (mirrors V26's device_role posture — a STRING column the JPA @Enumerated
--   maps, kept extensible so a future hint constant is a no-migration change).
ALTER TABLE device ADD COLUMN role_hint VARCHAR(32);
