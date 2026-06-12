package io.castellum.discovery;

import io.castellum.domain.Device;
import io.castellum.domain.DeviceRepository;
import io.castellum.domain.NetworkService;
import io.castellum.domain.NetworkServiceRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.test.context.TestPropertySource;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Repository-level contract for the PUBLIC-device TTL prune path, run against the REAL
 * Flyway H2 schema (same pattern as {@code CveCpeMatchRepositoryTest}). The default test
 * profile (Hibernate ddl-auto) generates NO service→device FK, so the cascade can only be
 * proven with the migrated schema — V2__create_service.sql declares
 * {@code device_id ... REFERENCES device(id) ON DELETE CASCADE}, which is what must clean
 * up service rows because JPQL bulk deletes ({@code deleteAllByIdInBatch}) bypass JPA cascade.
 */
@DataJpaTest
@TestPropertySource(properties = {
    "spring.flyway.enabled=true",
    "spring.flyway.locations=classpath:db/migration/h2",
    "spring.jpa.hibernate.ddl-auto=validate"
})
class DevicePruneRepositoryTest {

    private static final Instant NOW = Instant.parse("2026-06-12T00:00:00Z");
    private static final Instant CUTOFF = NOW.minus(Duration.ofDays(14));

    @Autowired private DeviceRepository deviceRepository;
    @Autowired private NetworkServiceRepository networkServiceRepository;
    @Autowired private TestEntityManager entityManager;

    private Device saveDevice(String ip, DiscoveryScope scope, Instant lastSeen) {
        Device d = new Device();
        d.setIpAddress(ip);
        d.setFirstSeen(lastSeen.minus(Duration.ofDays(10)));
        d.setLastSeen(lastSeen);
        d.setDiscoveryScope(scope);
        // criticality / deviceRole / roleConfidence / originHostIp ride on entity defaults.
        return deviceRepository.save(d);
    }

    private NetworkService saveService(Long deviceId) {
        NetworkService s = new NetworkService(null, deviceId, 443, "tcp", "https", null, NOW);
        return networkServiceRepository.save(s);
    }

    @Test
    void finder_returnsOnlyStalePublicDeviceIds() {
        Device stalePublic = saveDevice("203.0.113.10", DiscoveryScope.PUBLIC, NOW.minus(Duration.ofDays(20)));
        saveDevice("203.0.113.11", DiscoveryScope.PUBLIC, NOW.minus(Duration.ofDays(1)));  // fresh PUBLIC
        saveDevice("10.0.0.50", DiscoveryScope.HOME, NOW.minus(Duration.ofDays(20)));      // stale but HOME
        entityManager.flush();

        List<Long> ids = deviceRepository.findIdsByDiscoveryScopeAndLastSeenBefore(DiscoveryScope.PUBLIC, CUTOFF);

        assertThat(ids).containsExactly(stalePublic.getId());
    }

    @Test
    void bulkDeleteByIdInBatch_removesStaleDevice_cascadesServiceRow_survivorsIntact() {
        Device a = saveDevice("203.0.113.10", DiscoveryScope.PUBLIC, NOW.minus(Duration.ofDays(20)));
        Device b = saveDevice("203.0.113.11", DiscoveryScope.PUBLIC, NOW.minus(Duration.ofDays(1)));
        Device c = saveDevice("10.0.0.50", DiscoveryScope.HOME, NOW.minus(Duration.ofDays(20)));
        saveService(a.getId());
        entityManager.flush();

        List<Long> stale = deviceRepository.findIdsByDiscoveryScopeAndLastSeenBefore(DiscoveryScope.PUBLIC, CUTOFF);
        assertThat(stale).containsExactly(a.getId());

        // Same call path the prune service uses — a single JPQL bulk delete.
        deviceRepository.deleteAllByIdInBatch(stale);
        entityManager.flush();
        entityManager.clear(); // bulk delete bypasses the persistence context — re-read from DB

        assertThat(deviceRepository.findById(a.getId()))
            .as("stale PUBLIC device must be hard-deleted")
            .isEmpty();
        assertThat(deviceRepository.findById(b.getId()))
            .as("fresh PUBLIC device must survive")
            .isPresent();
        assertThat(deviceRepository.findById(c.getId()))
            .as("stale HOME device must survive — TTL applies to PUBLIC scope only")
            .isPresent();
        // DB-level FK ON DELETE CASCADE (V2__create_service.sql) must remove the child row,
        // because the JPQL bulk delete never consults JPA cascade metadata.
        assertThat(networkServiceRepository.findByDeviceId(a.getId()))
            .as("service row of the pruned device must be cascade-deleted by the DB FK")
            .isEmpty();
        assertThat(networkServiceRepository.count()).isZero();
    }
}
