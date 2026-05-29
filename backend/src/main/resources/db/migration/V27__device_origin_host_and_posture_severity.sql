-- V27: device origin host columns + composite IP uniqueness + service posture severity
--
-- (1) Add origin_host_ip (NOT NULL DEFAULT 'local') and origin_host_name (nullable) to device.
--     origin_host_ip='local' for all local-discovery paths; a remote docker probe writes the
--     probed host's IP. VARCHAR(45) covers IPv6-mapped addresses.
-- (2) Drop the single-column device_ip_unique constraint (added in V1) and replace it with a
--     composite UNIQUE(ip_address, origin_host_ip) named device_ip_origin_unique.
--     This allows two different docker hosts to each have a container at 172.17.0.2 (same internal
--     IP, different origin) while still preventing duplicate rows per origin.
-- (3) Add posture_severity (nullable) to the service table. A non-null value on a service row
--     (e.g. "CRITICAL" for an exposed docker daemon) contributes to the device's composite risk
--     independent of any matched CVE, surfaced in DeviceRiskService.compute().
ALTER TABLE device ADD COLUMN origin_host_ip VARCHAR(45) NOT NULL DEFAULT 'local';
ALTER TABLE device ADD COLUMN origin_host_name VARCHAR(255);
ALTER TABLE device DROP CONSTRAINT device_ip_unique;
ALTER TABLE device ADD CONSTRAINT device_ip_origin_unique UNIQUE (ip_address, origin_host_ip);
ALTER TABLE service ADD COLUMN posture_severity VARCHAR(16);
