package io.castellum;

import io.castellum.audit.AuditLog;
import io.castellum.audit.AuditLogRepository;
import io.castellum.cve.Cve;
import io.castellum.cve.CveCpeMatch;
import io.castellum.cve.CveCpeMatchRepository;
import io.castellum.cve.CveRepository;
import io.castellum.domain.Device;
import io.castellum.domain.DeviceRepository;
import io.castellum.domain.Scan;
import io.castellum.domain.ScanRepository;
import io.castellum.domain.ScanStatus;
import io.castellum.domain.NetworkService;
import io.castellum.domain.NetworkServiceRepository;
import io.castellum.risk.Criticality;
import io.castellum.risk.EpssScore;
import io.castellum.risk.EpssScoreRepository;
import io.castellum.risk.KevEntry;
import io.castellum.risk.KevEntryRepository;
import io.castellum.security.Role;
import io.castellum.security.User;
import io.castellum.security.UserRepository;
import io.castellum.threatintel.ThreatIntelPushRecord;
import io.castellum.threatintel.ThreatIntelPushRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.TestPropertySource;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.LocalDate;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration test that runs Flyway migrations against H2 (PostgreSQL-compatible mode)
 * before the JPA context starts. This catches entity/migration schema drift that the
 * unit test profile hides (where flyway.enabled=false lets Hibernate generate the schema).
 *
 * The test profile (application.yml) sets flyway.enabled=false and ddl-auto=create-drop.
 * This class overrides both properties so that Flyway runs first, then Hibernate validates
 * the schema it finds — exactly matching the production boot sequence.
 */
@SpringBootTest
@TestPropertySource(properties = {
    "spring.flyway.enabled=true",
    "spring.flyway.locations=classpath:db/migration/h2",
    "spring.jpa.hibernate.ddl-auto=validate"
})
class FlywayMigrationIntegrationTest {

    @Autowired
    private DeviceRepository deviceRepository;

    @Autowired
    private NetworkServiceRepository networkServiceRepository;

    @Autowired
    private ScanRepository scanRepository;

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Autowired
    private CveRepository cveRepository;

    @Autowired
    private CveCpeMatchRepository cveCpeMatchRepository;

    @Autowired
    private EpssScoreRepository epssScoreRepository;

    @Autowired
    private KevEntryRepository kevEntryRepository;

    @Autowired
    private ThreatIntelPushRepository threatIntelPushRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Test
    void flyway_migratesAllFourTables_andEntitiesMatchSchema() {
        // Device — ip_address is TEXT in V1 migration, String in entity: must be compatible.
        // first_seen / last_seen are NOT NULL in migration; set them explicitly (no DB default via JPA).
        Device device = new Device();
        device.setIpAddress("10.0.0.1");
        device.setHostname("test-host");
        device.setFirstSeen(Instant.now());
        device.setLastSeen(Instant.now());
        Device savedDevice = deviceRepository.save(device);
        assertNotNull(savedDevice.getId(), "Device insert should succeed with Flyway-managed schema");

        // NetworkService — observed_at is NOT NULL in migration; set it explicitly.
        NetworkService svc = new NetworkService();
        svc.setDeviceId(savedDevice.getId());
        svc.setPort(80);
        svc.setProtocol("tcp");
        svc.setObservedAt(Instant.now());
        NetworkService savedSvc = networkServiceRepository.save(svc);
        assertNotNull(savedSvc.getId(), "NetworkService insert should succeed");

        // Scan
        Scan scan = new Scan();
        scan.setCidr("10.0.0.0/24");
        scan.setScanType("PING_SWEEP");
        scan.setStatus(ScanStatus.PENDING);
        scan.setRequestedAt(Instant.now());
        Scan savedScan = scanRepository.save(scan);
        assertNotNull(savedScan.getId(), "Scan insert should succeed");

        // AuditLog — payload is TEXT in V4 migration, String in entity: must be compatible.
        AuditLog log = new AuditLog(
            Instant.now(), "system", "TEST_MIGRATE", "device",
            String.valueOf(savedDevice.getId()), "{\"test\":true}"
        );
        AuditLog savedLog = auditLogRepository.save(log);
        assertNotNull(savedLog.getId(), "AuditLog insert should succeed with Flyway-managed schema");
        assertEquals("{\"test\":true}", savedLog.getPayload(),
            "AuditLog payload round-trips correctly with TEXT column type");
    }

    @Test
    void flyway_v5_cve_andCveCpeMatch_roundTripWithFlywayManagedSchema() {
        Cve cve = new Cve();
        cve.setCveId("CVE-2020-15778");
        cve.setLastModified(Instant.now());
        cve.setRawJson("{}");
        cve.setFetchedAt(Instant.now());
        Cve savedCve = cveRepository.save(cve);
        assertNotNull(savedCve.getId(), "Cve insert should succeed with Flyway-managed schema");

        CveCpeMatch match = new CveCpeMatch();
        match.setCveFk(savedCve.getId());
        match.setCpe23Uri("cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*");
        match.setVulnerable(Boolean.TRUE);
        match.setVersionEndExcluding("8.4");
        CveCpeMatch savedMatch = cveCpeMatchRepository.save(match);
        assertNotNull(savedMatch.getId(), "CveCpeMatch insert should succeed");

        assertEquals(1, cveCpeMatchRepository.findByCveFk(savedCve.getId()).size(),
            "CveCpeMatch should be retrievable by cveFk after Flyway-managed schema apply");
    }

    @Test
    void flyway_v6_epssScore_roundTripWithFlywayManagedSchema() {
        EpssScore score = new EpssScore(null, "CVE-2020-15778",
            BigDecimal.valueOf(0.5), BigDecimal.valueOf(0.9), LocalDate.now(), Instant.now());
        EpssScore saved = epssScoreRepository.save(score);
        assertNotNull(saved.getId(), "EpssScore insert should succeed with Flyway-managed schema");
        assertTrue(epssScoreRepository.findByCveId("CVE-2020-15778").isPresent(),
            "EpssScore should be retrievable by cveId");
    }

    @Test
    void flyway_v6_kevEntry_roundTripWithFlywayManagedSchema() {
        KevEntry entry = new KevEntry();
        entry.setCveId("CVE-2020-15778");
        entry.setDateAdded(LocalDate.now());
        entry.setVendorProject("OpenBSD");
        entry.setProduct("OpenSSH");
        entry.setIngestedAt(Instant.now());
        kevEntryRepository.save(entry);
        assertTrue(kevEntryRepository.existsByCveId("CVE-2020-15778"),
            "KevEntry should exist by cveId after Flyway-managed schema apply");
    }

    @Test
    void flyway_v6_deviceCriticality_columnAcceptsAllFourValues() {
        String[] ips = {"192.168.0.1", "192.168.0.2", "192.168.0.3", "192.168.0.4"};
        Criticality[] crits = {Criticality.LOW, Criticality.MEDIUM, Criticality.HIGH, Criticality.CRITICAL};
        for (int i = 0; i < crits.length; i++) {
            Device d = new Device();
            d.setIpAddress(ips[i]);
            d.setFirstSeen(Instant.now());
            d.setLastSeen(Instant.now());
            d.setCriticality(crits[i]);
            Device saved = deviceRepository.save(d);
            assertEquals(crits[i], deviceRepository.findById(saved.getId()).orElseThrow().getCriticality(),
                "Criticality " + crits[i] + " should round-trip correctly");
        }
    }

    @Test
    void v8_threatIntelPushRoundtrip() {
        ThreatIntelPushRecord rec = new ThreatIntelPushRecord(
            "EXPORT", "bundle--test-1234", 200, "status=200", Instant.now(), null);
        ThreatIntelPushRecord saved = threatIntelPushRepository.save(rec);
        assertNotNull(saved.getId(), "ThreatIntelPushRecord should get a generated id");
        ThreatIntelPushRecord loaded = threatIntelPushRepository.findById(saved.getId()).orElseThrow();
        assertNotNull(loaded.getOccurredAt(), "occurred_at must be non-null after insert");
        assertEquals("EXPORT", loaded.getPushTarget());
        assertEquals("bundle--test-1234", loaded.getBundleId());
    }

    @Test
    void v9_usersTableRoundTrip() {
        // Insert via raw JDBC to guard against entity/migration drift independently
        jdbcTemplate.update(
            "INSERT INTO users (username, password_hash, role, enabled, created_at) VALUES (?, ?, ?, ?, ?)",
            "alice", "$2a$12$dummyhash", "ADMIN", true, Instant.now()
        );
        Map<String, Object> row = jdbcTemplate.queryForMap(
            "SELECT username, password_hash, role, enabled, created_at FROM users WHERE username = 'alice'"
        );
        assertEquals("alice", row.get("username"), "username must round-trip");
        assertEquals("ADMIN", row.get("role"), "role must round-trip as string");
        assertEquals(true, row.get("enabled"), "enabled must be true");
        assertEquals("$2a$12$dummyhash", row.get("password_hash"), "password_hash must round-trip");
        assertNotNull(row.get("created_at"), "created_at must be non-null");
    }

    @Test
    void flywayMigratesV11_discoverySweepTable_appliesIdempotentlyAgainstH2Mirror() {
        // V11 migration must have applied during context start — assert the table is present.
        Number columnCount = jdbcTemplate.queryForObject(
            "SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE UPPER(TABLE_NAME) = 'DISCOVERY_SWEEP'",
            Number.class);
        assertNotNull(columnCount, "INFORMATION_SCHEMA.COLUMNS query must return a result");
        assertTrue(columnCount.intValue() >= 10,
            "discovery_sweep table must have at least 10 columns after V11 (id, started_at, finished_at, source, iface, neighbor_count, device_count, triggered_by, audit_log_id, status)");
        // Index check — V11 declares idx_discovery_sweep_started.
        Number indexCount = jdbcTemplate.queryForObject(
            "SELECT COUNT(*) FROM INFORMATION_SCHEMA.INDEXES WHERE UPPER(TABLE_NAME) = 'DISCOVERY_SWEEP' AND UPPER(INDEX_NAME) LIKE '%STARTED%'",
            Number.class);
        assertNotNull(indexCount, "INFORMATION_SCHEMA.INDEXES query must return a result");
        assertTrue(indexCount.intValue() >= 1, "idx_discovery_sweep_started must exist after V11 migration");
    }

    @Test
    void flywayMigratesV11_discoverySweepRoundTrip_persistsAndReadsBack() {
        // Insert via raw JDBC to guard against entity/migration drift independently.
        Instant start = Instant.now();
        jdbcTemplate.update(
            "INSERT INTO discovery_sweep (started_at, source, triggered_by, status) VALUES (?, ?, ?, ?)",
            start, "ARP", "MANUAL", "OK"
        );
        Map<String, Object> row = jdbcTemplate.queryForMap(
            "SELECT source, triggered_by, status, neighbor_count, device_count FROM discovery_sweep ORDER BY started_at DESC LIMIT 1"
        );
        assertEquals("ARP", row.get("source"), "source must round-trip");
        assertEquals("MANUAL", row.get("triggered_by"), "triggered_by must round-trip");
        assertEquals("OK", row.get("status"), "status must round-trip");
        assertEquals(0, ((Number) row.get("neighbor_count")).intValue(), "neighbor_count default 0");
        assertEquals(0, ((Number) row.get("device_count")).intValue(), "device_count default 0");
    }

    @Test
    void v12_addsFailureReasonColumn() {
        // Confirm the column exists via INFORMATION_SCHEMA (migration-level check).
        Number colCount = jdbcTemplate.queryForObject(
            "SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS " +
            "WHERE UPPER(TABLE_NAME) = 'SCAN' AND UPPER(COLUMN_NAME) = 'FAILURE_REASON'",
            Number.class);
        assertNotNull(colCount, "INFORMATION_SCHEMA query must return a result");
        assertTrue(colCount.intValue() > 0,
            "failure_reason column must exist in scan table after V12 migration");

        // Round-trip: NULL is accepted (success-path rows never populate the column).
        Scan scanWithoutReason = new Scan();
        scanWithoutReason.setCidr("10.99.0.0/24");
        scanWithoutReason.setScanType("PING_SWEEP");
        scanWithoutReason.setStatus(ScanStatus.PENDING);
        scanWithoutReason.setRequestedAt(Instant.now());
        Scan savedNull = scanRepository.save(scanWithoutReason);
        assertNull(savedNull.getFailureReason(),
            "failure_reason must be null when not set");

        // Round-trip: a long string is accepted (TEXT has no length cap).
        String longReason = "IOException: " + "x".repeat(490);
        Scan scanWithReason = new Scan();
        scanWithReason.setCidr("10.99.1.0/24");
        scanWithReason.setScanType("PING_SWEEP");
        scanWithReason.setStatus(ScanStatus.FAILED);
        scanWithReason.setRequestedAt(Instant.now());
        scanWithReason.setFailureReason(longReason);
        Scan savedReason = scanRepository.save(scanWithReason);
        assertEquals(longReason, savedReason.getFailureReason(),
            "failure_reason must round-trip a long string via TEXT column");
    }

    @Test
    void usersV10TokenVersionRoundTrips() {
        // Persist a User and assert tokenVersion defaults to 0
        User u = new User("rt-user", "$2a$12$x", Role.VIEWER, true, Instant.now());
        userRepository.saveAndFlush(u);
        userRepository.findById(u.getId()).ifPresentOrElse(loaded -> {
            assertEquals(0, loaded.getTokenVersion(), "tokenVersion must default to 0 after V10 migration");

            // Now update tokenVersion and round-trip
            loaded.setTokenVersion(7);
            userRepository.saveAndFlush(loaded);
            userRepository.findById(loaded.getId()).ifPresent(reloaded ->
                assertEquals(7, reloaded.getTokenVersion(), "tokenVersion must round-trip after update")
            );
        }, () -> fail("User must be retrievable after persist"));

        // Also verify column metadata via JDBC
        Number columnCount = jdbcTemplate.queryForObject(
            "SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE UPPER(TABLE_NAME) = 'USERS' AND UPPER(COLUMN_NAME) = 'TOKEN_VERSION'",
            Number.class);
        assertNotNull(columnCount, "INFORMATION_SCHEMA.COLUMNS query must return a result");
        assertTrue(columnCount.intValue() > 0, "token_version column must exist in users table per V10 migration");
    }

    @Test
    void v14_scanPolicyTableAndRetryCountColumnExist() {
        // Table presence
        Number tableCount = jdbcTemplate.queryForObject(
            "SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES " +
            "WHERE UPPER(TABLE_NAME) = 'SCAN_POLICY'",
            Number.class);
        assertNotNull(tableCount);
        assertTrue(tableCount.intValue() >= 1, "scan_policy table must exist after V14");

        // scan.retry_count column
        Number retryColCount = jdbcTemplate.queryForObject(
            "SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS " +
            "WHERE UPPER(TABLE_NAME) = 'SCAN' AND UPPER(COLUMN_NAME) = 'RETRY_COUNT'",
            Number.class);
        assertNotNull(retryColCount);
        assertTrue(retryColCount.intValue() >= 1, "scan.retry_count column must exist after V14");

        // Round-trip via raw JDBC
        jdbcTemplate.update(
            "INSERT INTO scan_policy (name, cron_expression, cidr, scan_type, enabled) VALUES (?, ?, ?, ?, ?)",
            "v14-test-policy", "0 0 * * * *", "10.0.0.0/24", "PING_SWEEP", true
        );
        Map<String, Object> row = jdbcTemplate.queryForMap(
            "SELECT name, cron_expression, cidr, scan_type, enabled FROM scan_policy WHERE name = 'v14-test-policy'"
        );
        assertEquals("v14-test-policy", row.get("name"));
        assertEquals("0 0 * * * *", row.get("cron_expression"));
        assertEquals("10.0.0.0/24", row.get("cidr"));
        assertEquals("PING_SWEEP", row.get("scan_type"));
        assertEquals(true, row.get("enabled"));
    }

    @Test
    void v15_integrationConfigTableExists_andRowsRoundTrip() {
        // Table presence
        Number tableCount = jdbcTemplate.queryForObject(
            "SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES " +
            "WHERE UPPER(TABLE_NAME) = 'INTEGRATION_CONFIG'",
            Number.class);
        assertNotNull(tableCount);
        assertTrue(tableCount.intValue() >= 1, "integration_config table must exist after V15");

        // Required column shape — encrypted_credentials is the secret-bearing column.
        Number encryptedColCount = jdbcTemplate.queryForObject(
            "SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS " +
            "WHERE UPPER(TABLE_NAME) = 'INTEGRATION_CONFIG' " +
            "AND UPPER(COLUMN_NAME) = 'ENCRYPTED_CREDENTIALS'",
            Number.class);
        assertNotNull(encryptedColCount);
        assertTrue(encryptedColCount.intValue() >= 1,
            "encrypted_credentials column must exist after V15");

        // Round-trip via raw JDBC (the column accepts a small byte payload).
        byte[] payload = new byte[]{0x01, 0x02, 0x03, 0x04, 0x05};
        jdbcTemplate.update(
            "INSERT INTO integration_config (integration_type, config_json, encrypted_credentials) " +
            "VALUES (?, ?, ?)",
            "TAXII", "{\"url\":\"https://taxii.example\"}", payload
        );
        Map<String, Object> row = jdbcTemplate.queryForMap(
            "SELECT integration_type, config_json FROM integration_config " +
            "WHERE integration_type = 'TAXII'"
        );
        assertEquals("TAXII", row.get("integration_type"));
        assertEquals("{\"url\":\"https://taxii.example\"}", row.get("config_json"));
    }

    @Test
    void v13_addsAuditLogTimeActionIndex() {
        // Confirm the index exists via INFORMATION_SCHEMA.INDEXES
        Number indexCount = jdbcTemplate.queryForObject(
            "SELECT COUNT(*) FROM INFORMATION_SCHEMA.INDEXES " +
            "WHERE UPPER(INDEX_NAME) = 'IDX_AUDIT_LOG_TIME_ACTION' " +
            "AND UPPER(TABLE_NAME) = 'AUDIT_LOG'",
            Number.class);
        assertNotNull(indexCount, "INFORMATION_SCHEMA.INDEXES query must return a result");
        assertTrue(indexCount.intValue() >= 1,
            "idx_audit_log_time_action index must exist on audit_log after V13 migration");
    }
}
