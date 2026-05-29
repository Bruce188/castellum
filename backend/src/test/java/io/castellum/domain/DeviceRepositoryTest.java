package io.castellum.domain;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.dao.DataIntegrityViolationException;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@DataJpaTest
class DeviceRepositoryTest {

    @Autowired
    private TestEntityManager em;

    @Autowired
    private DeviceRepository repository;

    @Test
    void saveAndFindById_preservesIpAddressAndHostname() {
        Device device = new Device();
        device.setIpAddress("192.168.1.1");
        device.setHostname("test-host");
        device.setFirstSeen(Instant.now());
        device.setLastSeen(Instant.now());

        Device saved = repository.save(device);
        Optional<Device> found = repository.findById(saved.getId());

        assertTrue(found.isPresent());
        assertEquals("192.168.1.1", found.get().getIpAddress());
        assertEquals("test-host", found.get().getHostname());
    }

    /**
     * Schema-enabling round-trip: persists a Device with both scan-attribution columns set,
     * reloads via the repository, and asserts they survive the JPA flush/load cycle.
     *
     * <p>This test passes once the V25 columns exist in the H2 schema (via Hibernate DDL from
     * the entity fields) AND the {@code @Column} mappings on {@code Device} are correct.
     * The behavioral invariants (discovered set INSERT-only, last_seen set INSERT+UPDATE,
     * non-scan callers unaffected) are verified separately in Task 1.2's
     * {@code DeviceUpsertServiceTest}.</p>
     */
    @Test
    void scanAttributionColumns_roundTripThroughRepository() {
        Device device = new Device();
        device.setIpAddress("10.99.0.1");
        device.setFirstSeen(Instant.now());
        device.setLastSeen(Instant.now());
        device.setDiscoveredByScanId(42L);
        device.setLastSeenByScanId(99L);

        Device saved = repository.saveAndFlush(device);
        em.clear(); // evict from first-level cache to force DB read
        Device reloaded = repository.findById(saved.getId()).orElseThrow();

        assertEquals(42L, reloaded.getDiscoveredByScanId(), "discoveredByScanId must round-trip");
        assertEquals(99L, reloaded.getLastSeenByScanId(),  "lastSeenByScanId must round-trip");
    }

    /**
     * Devices that predate V25 (and non-scan-discovered devices) must carry NULL in both
     * attribution columns — the columns are nullable with no default.
     */
    @Test
    void scanAttributionColumns_nullByDefault() {
        Device device = new Device();
        device.setIpAddress("10.99.0.2");
        device.setFirstSeen(Instant.now());
        device.setLastSeen(Instant.now());
        // deliberately NOT setting discoveredByScanId or lastSeenByScanId

        Device saved = repository.saveAndFlush(device);
        em.clear();
        Device reloaded = repository.findById(saved.getId()).orElseThrow();

        assertNull(reloaded.getDiscoveredByScanId(), "discoveredByScanId must be null when not set");
        assertNull(reloaded.getLastSeenByScanId(),   "lastSeenByScanId must be null when not set");
    }

    @Test
    void duplicateIpAddress_throwsDataIntegrityViolationException() {
        Device d1 = new Device();
        d1.setIpAddress("10.0.0.1");
        d1.setFirstSeen(Instant.now());
        d1.setLastSeen(Instant.now());
        repository.save(d1);

        Device d2 = new Device();
        d2.setIpAddress("10.0.0.1");
        d2.setFirstSeen(Instant.now());
        d2.setLastSeen(Instant.now());

        assertThrows(DataIntegrityViolationException.class, () -> {
            repository.saveAndFlush(d2);
        });
    }
}
