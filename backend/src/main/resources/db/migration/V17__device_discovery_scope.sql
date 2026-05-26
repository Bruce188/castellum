-- V17: device.discovery_scope column with backfill
--
-- Discovery scope discriminator surfaced in the topology UI so the
-- operator can tell home-LAN devices apart from Docker-bridge siblings,
-- IPv4 link-local APIPA leakage, and loopback. NOT NULL with default
-- 'HOME' so existing rows backfill non-null, and the JPA entity field
-- can keep its non-null contract.

ALTER TABLE device
    ADD COLUMN discovery_scope VARCHAR(32) NOT NULL DEFAULT 'HOME';

UPDATE device SET discovery_scope = CASE
    WHEN ip_address LIKE '127.%'                                 THEN 'LOOPBACK'
    WHEN ip_address LIKE '169.254.%'                             THEN 'LINK_LOCAL'
    WHEN ip_address LIKE '172.17.%' OR ip_address LIKE '172.18.%' THEN 'DOCKER_BRIDGE'
    WHEN ip_address LIKE '192.168.%' OR ip_address LIKE '10.%'   THEN 'HOME'
    WHEN ip_address ~ '^172\.(1[6-9]|2[0-9]|3[01])\.'            THEN 'HOME'
    ELSE 'PUBLIC'
END;
