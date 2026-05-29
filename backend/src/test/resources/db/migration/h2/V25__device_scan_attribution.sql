-- V25: device scan-attribution columns
--
-- Records which scan first discovered a device (discovered_by_scan_id, INSERT-once)
-- and which scan most recently observed it (last_seen_by_scan_id, last-writer-wins).
-- Both are nullable: devices seeded before V25, and all non-scan-discovered devices,
-- carry NULL. No FK constraint — mirrors the loose scan-id referencing used elsewhere.
ALTER TABLE device ADD COLUMN discovered_by_scan_id BIGINT;
ALTER TABLE device ADD COLUMN last_seen_by_scan_id BIGINT;
