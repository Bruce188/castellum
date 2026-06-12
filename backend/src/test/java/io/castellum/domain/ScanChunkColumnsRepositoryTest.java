package io.castellum.domain;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.test.context.TestPropertySource;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Entity/migration contract for the V31 chunk columns, run against the REAL Flyway H2
 * schema with {@code ddl-auto=validate} (same pattern as {@code DevicePruneRepositoryTest}):
 * the Scan entity's new fields ({@code skipHostDiscovery}, {@code chunksTotal},
 * {@code chunksDone}) must round-trip through the migrated {@code scan} table, proving
 * entity and V31 migration agree.
 */
@DataJpaTest
@TestPropertySource(properties = {
    "spring.flyway.enabled=true",
    "spring.flyway.locations=classpath:db/migration/h2",
    "spring.jpa.hibernate.ddl-auto=validate"
})
class ScanChunkColumnsRepositoryTest {

    @Autowired private ScanRepository scanRepository;
    @Autowired private TestEntityManager entityManager;

    @Test
    void chunkFieldsAndSkipFlag_roundTripThroughFlywaySchema() {
        Scan scan = new Scan();
        scan.setCidr("10.0.0.0/20");
        scan.setScanType("PING_SWEEP");
        scan.setStatus(ScanStatus.RUNNING);
        scan.setRequestedAt(Instant.parse("2026-06-01T00:00:00Z"));
        scan.setSkipHostDiscovery(true);
        scan.setChunksTotal(4);
        scan.setChunksDone(2);

        Long id = scanRepository.save(scan).getId();
        entityManager.flush();
        entityManager.clear();

        Scan reloaded = scanRepository.findById(id).orElseThrow();
        assertThat(reloaded.isSkipHostDiscovery())
            .as("skip_host_discovery must round-trip TRUE")
            .isTrue();
        assertThat(reloaded.getChunksTotal())
            .as("chunks_total must round-trip")
            .isEqualTo(4);
        assertThat(reloaded.getChunksDone())
            .as("chunks_done must round-trip")
            .isEqualTo(2);
    }

    @Test
    void newScan_defaultsFlagFalse_andChunkCountersNullable() {
        Scan scan = new Scan();
        scan.setCidr("10.0.1.0/24");
        scan.setScanType("PING_SWEEP");
        scan.setStatus(ScanStatus.PENDING);
        scan.setRequestedAt(Instant.parse("2026-06-01T00:00:00Z"));
        // skipHostDiscovery / chunksTotal / chunksDone deliberately untouched.

        Long id = scanRepository.save(scan).getId();
        entityManager.flush();
        entityManager.clear();

        Scan reloaded = scanRepository.findById(id).orElseThrow();
        assertThat(reloaded.isSkipHostDiscovery())
            .as("skipHostDiscovery must default to false")
            .isFalse();
        assertThat(reloaded.getChunksTotal())
            .as("chunks_total is nullable — unset on a fresh PENDING row")
            .isNull();
        assertThat(reloaded.getChunksDone())
            .as("chunks_done is nullable — unset on a fresh PENDING row")
            .isNull();
    }
}
