-- V19: device.discovery_source column
--
-- Records how each device was most recently discovered. Nullable because
-- existing rows have no provenance signal; new rows are populated at upsert
-- time by DeviceUpsertService (last-writer-wins, mirroring lastSeen).
-- VARCHAR(32) matches the DiscoverySource enum name length contract.

ALTER TABLE device ADD COLUMN discovery_source VARCHAR(32);
