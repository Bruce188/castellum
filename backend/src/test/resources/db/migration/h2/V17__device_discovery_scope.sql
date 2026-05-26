-- V17 (H2 mirror): device.discovery_scope column with backfill
--
-- H2-compatible version of V17__device_discovery_scope.sql for Flyway
-- integration tests. Differences from production script:
--   PostgreSQL '~' regex operator -> H2 REGEXP_LIKE(string, pattern).
-- Backfill semantics are identical: classify legacy rows by ip_address
-- pattern so the new NOT NULL column has values for every prior insert.

ALTER TABLE device
    ADD COLUMN discovery_scope VARCHAR(32) NOT NULL DEFAULT 'HOME';

UPDATE device SET discovery_scope = CASE
    WHEN ip_address LIKE '127.%'                                              THEN 'LOOPBACK'
    WHEN ip_address LIKE '169.254.%'                                          THEN 'LINK_LOCAL'
    WHEN ip_address LIKE '172.17.%' OR ip_address LIKE '172.18.%'             THEN 'DOCKER_BRIDGE'
    WHEN ip_address LIKE '192.168.%' OR ip_address LIKE '10.%'                THEN 'HOME'
    WHEN REGEXP_LIKE(ip_address, '^172\.(1[6-9]|2[0-9]|3[01])\.')             THEN 'HOME'
    ELSE 'PUBLIC'
END;
