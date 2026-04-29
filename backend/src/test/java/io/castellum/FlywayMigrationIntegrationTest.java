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
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

import java.time.Instant;

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
}
