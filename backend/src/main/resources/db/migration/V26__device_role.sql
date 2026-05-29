-- V26: device.device_role column
--
-- Explicit role classification (LAPTOP/DESKTOP/SERVER/ROUTER/CONTAINER/UNKNOWN)
-- populated at upsert time by DeviceRoleClassifier. NOT NULL DEFAULT 'UNKNOWN'
-- migrates existing rows cleanly. VARCHAR(32) matches the enum-name length
-- contract used by discovery_source (V19).
ALTER TABLE device ADD COLUMN device_role VARCHAR(32) NOT NULL DEFAULT 'UNKNOWN';
