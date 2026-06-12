package io.castellum.discovery;

import io.castellum.domain.Device;
import io.castellum.domain.DeviceRepository;
import io.castellum.domain.DeviceRepository.StaleDeviceSample;
import io.castellum.domain.NetworkService;
import io.castellum.domain.NetworkServiceRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.test.context.TestPropertySource;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static io.castellum.discovery.DevicePruneService.PRUNABLE_SOURCES;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Repository-level contract for the PUBLIC-device TTL prune path, run against the REAL
 * Flyway H2 schema (same pattern as {@code CveCpeMatchRepositoryTest}). The default test
 * profile (Hibernate ddl-auto) generates NO service→device FK, so the cascade can only be
 * proven with the migrated schema — V2__create_service.sql declares
 * {@code device_id ... REFERENCES device(id) ON DELETE CASCADE}, which is what must clean
 * up service rows because JPQL bulk deletes bypass JPA cascade metadata.
 *
 * <p>Pins the full prune predicate of {@code deleteStaleByScopeAndSources}: PUBLIC scope,
 * strict {@code lastSeen < cutoff} (a row exactly AT the cutoff is kept), no scan
 * attribution, and a discovery source on the passive allowlist (NMAP_SCAN / OT_PROBE /
 * NULL-source rows are never pruned).
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

    private Device saveDevice(String ip, DiscoveryScope scope, Instant lastSeen, DiscoverySource source) {
        Device d = new Device();
        d.setIpAddress(ip);
        d.setFirstSeen(lastSeen.minus(Duration.ofDays(10)));
        d.setLastSeen(lastSeen);
        d.setDiscoveryScope(scope);
        d.setDiscoverySource(source);
        // criticality / deviceRole / roleConfidence / originHostIp ride on entity defaults.
        return deviceRepository.save(d);
    }

    private NetworkService saveService(Long deviceId) {
        NetworkService s = new NetworkService(null, deviceId, 443, "tcp", "https", null, NOW);
        return networkServiceRepository.save(s);
    }

    @Test
    void predicateDelete_removesOnlyStalePassivePublicDevices_cascadesServiceRow() {
        Device stalePassive = saveDevice("203.0.113.10", DiscoveryScope.PUBLIC,
            NOW.minus(Duration.ofDays(20)), DiscoverySource.CONN_TABLE);
        Device freshPublic = saveDevice("203.0.113.11", DiscoveryScope.PUBLIC,
            NOW.minus(Duration.ofDays(1)), DiscoverySource.CONN_TABLE);
        Device staleHome = saveDevice("10.0.0.50", DiscoveryScope.HOME,
            NOW.minus(Duration.ofDays(20)), DiscoverySource.CONN_TABLE);
        Device boundary = saveDevice("203.0.113.12", DiscoveryScope.PUBLIC,
            CUTOFF, DiscoverySource.CONN_TABLE);
        Device scanObserved = saveDevice("203.0.113.13", DiscoveryScope.PUBLIC,
            NOW.minus(Duration.ofDays(20)), DiscoverySource.CONN_TABLE);
        scanObserved.setLastSeenByScanId(99L);
        Device scanDiscovered = saveDevice("203.0.113.14", DiscoveryScope.PUBLIC,
            NOW.minus(Duration.ofDays(20)), DiscoverySource.CONN_TABLE);
        scanDiscovered.setDiscoveredByScanId(98L);
        Device nmapScanned = saveDevice("203.0.113.15", DiscoveryScope.PUBLIC,
            NOW.minus(Duration.ofDays(20)), DiscoverySource.NMAP_SCAN);
        Device otProbed = saveDevice("203.0.113.16", DiscoveryScope.PUBLIC,
            NOW.minus(Duration.ofDays(20)), DiscoverySource.OT_PROBE);
        Device manual = saveDevice("203.0.113.17", DiscoveryScope.PUBLIC,
            NOW.minus(Duration.ofDays(20)), null);
        saveService(stalePassive.getId());
        entityManager.flush();

        // Same call path the prune service uses — a single atomic predicate delete.
        int deleted = deviceRepository.deleteStaleByScopeAndSources(
            DiscoveryScope.PUBLIC, CUTOFF, PRUNABLE_SOURCES);
        entityManager.clear(); // bulk delete bypasses the persistence context — re-read from DB

        assertThat(deleted).isEqualTo(1);
        assertThat(deviceRepository.findById(stalePassive.getId()))
            .as("stale passively-observed PUBLIC device must be hard-deleted")
            .isEmpty();
        assertThat(deviceRepository.findById(freshPublic.getId()))
            .as("fresh PUBLIC device must survive")
            .isPresent();
        assertThat(deviceRepository.findById(staleHome.getId()))
            .as("stale HOME device must survive — TTL applies to PUBLIC scope only")
            .isPresent();
        assertThat(deviceRepository.findById(boundary.getId()))
            .as("device with lastSeen exactly AT the cutoff must survive — strict '<'")
            .isPresent();
        assertThat(deviceRepository.findById(scanObserved.getId()))
            .as("device with lastSeenByScanId must survive — scan attribution exempts it")
            .isPresent();
        assertThat(deviceRepository.findById(scanDiscovered.getId()))
            .as("device with discoveredByScanId must survive — scan attribution exempts it")
            .isPresent();
        assertThat(deviceRepository.findById(nmapScanned.getId()))
            .as("NMAP_SCAN-sourced device must survive — lastSeen means 'last scanned'")
            .isPresent();
        assertThat(deviceRepository.findById(otProbed.getId()))
            .as("OT_PROBE-sourced device must survive — deliberately probed asset")
            .isPresent();
        assertThat(deviceRepository.findById(manual.getId()))
            .as("NULL-source (manually created) device must survive — IN list never matches NULL")
            .isPresent();
        // DB-level FK ON DELETE CASCADE (V2__create_service.sql) must remove the child row,
        // because the JPQL bulk delete never consults JPA cascade metadata.
        assertThat(networkServiceRepository.findByDeviceId(stalePassive.getId()))
            .as("service row of the pruned device must be cascade-deleted by the DB FK")
            .isEmpty();
        assertThat(networkServiceRepository.count()).isZero();
    }

    @Test
    void sampleFinder_returnsIdentityTuples_forPruneEligibleRowsOnly_oldestFirst() {
        Device older = saveDevice("203.0.113.10", DiscoveryScope.PUBLIC,
            NOW.minus(Duration.ofDays(30)), DiscoverySource.CONN_TABLE);
        Device newer = saveDevice("203.0.113.11", DiscoveryScope.PUBLIC,
            NOW.minus(Duration.ofDays(20)), DiscoverySource.GATEWAY);
        saveDevice("203.0.113.12", DiscoveryScope.PUBLIC, NOW.minus(Duration.ofDays(1)),
            DiscoverySource.CONN_TABLE);                                       // fresh
        saveDevice("203.0.113.13", DiscoveryScope.PUBLIC, CUTOFF,
            DiscoverySource.CONN_TABLE);                                       // boundary
        saveDevice("203.0.113.14", DiscoveryScope.PUBLIC, NOW.minus(Duration.ofDays(20)),
            DiscoverySource.NMAP_SCAN);                                        // scan-sourced
        saveDevice("203.0.113.15", DiscoveryScope.PUBLIC, NOW.minus(Duration.ofDays(20)),
            null);                                                             // manual
        saveDevice("10.0.0.50", DiscoveryScope.HOME, NOW.minus(Duration.ofDays(20)),
            DiscoverySource.CONN_TABLE);                                       // wrong scope
        entityManager.flush();

        List<StaleDeviceSample> samples = deviceRepository.findStaleSamplesByScopeAndSources(
            DiscoveryScope.PUBLIC, CUTOFF, PRUNABLE_SOURCES,
            PageRequest.of(0, 50, Sort.by("lastSeen")));

        assertThat(samples)
            .extracting(StaleDeviceSample::getId, StaleDeviceSample::getIpAddress,
                        StaleDeviceSample::getOriginHostIp, StaleDeviceSample::getLastSeen)
            .as("sample must carry the identity tuple of prune-eligible rows only, oldest first")
            .containsExactly(
                org.assertj.core.groups.Tuple.tuple(older.getId(), "203.0.113.10", "local",
                    NOW.minus(Duration.ofDays(30))),
                org.assertj.core.groups.Tuple.tuple(newer.getId(), "203.0.113.11", "local",
                    NOW.minus(Duration.ofDays(20))));
    }

    @Test
    void sampleFinder_respectsPageableCap() {
        saveDevice("203.0.113.10", DiscoveryScope.PUBLIC, NOW.minus(Duration.ofDays(30)),
            DiscoverySource.CONN_TABLE);
        saveDevice("203.0.113.11", DiscoveryScope.PUBLIC, NOW.minus(Duration.ofDays(25)),
            DiscoverySource.CONN_TABLE);
        saveDevice("203.0.113.12", DiscoveryScope.PUBLIC, NOW.minus(Duration.ofDays(20)),
            DiscoverySource.CONN_TABLE);
        entityManager.flush();

        List<StaleDeviceSample> samples = deviceRepository.findStaleSamplesByScopeAndSources(
            DiscoveryScope.PUBLIC, CUTOFF, PRUNABLE_SOURCES,
            PageRequest.of(0, 2, Sort.by("lastSeen")));

        // The 50-row production cap rides on the same Pageable mechanism asserted here.
        assertThat(samples).hasSize(2);
        assertThat(samples.get(0).getIpAddress()).isEqualTo("203.0.113.10");
        assertThat(samples.get(1).getIpAddress()).isEqualTo("203.0.113.11");
    }
}
