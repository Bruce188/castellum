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
}
