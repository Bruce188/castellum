-- V30: device network_name column
--
-- Adds nullable network_name VARCHAR(255) to device.
-- Populated by DockerDiscoveryService.ingest() from the container's primary docker
-- network name (e.g. "bridge", "pingpay_default"). Null for non-docker and legacy rows.
-- No default, no constraint change, plain additive column.
ALTER TABLE device ADD COLUMN network_name VARCHAR(255);
