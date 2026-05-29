package io.castellum.discovery;

import io.castellum.domain.Device;
import io.castellum.domain.DeviceRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.context.annotation.Import;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
@Import({DeviceUpsertService.class, DiscoveryScopeClassifier.class})
class DeviceUpsertServiceTest {

    @Autowired
    private DeviceUpsertService service;

    @Autowired
    private DeviceRepository repo;

    private static final Instant T1 = Instant.parse("2026-04-29T10:00:00Z");
    private static final Instant T2 = Instant.parse("2026-04-29T11:00:00Z");

    @BeforeEach
    void setUp() {
        repo.deleteAll();
    }

    @Test
    void upsert_newIp_insertsNewRow() {
        Discovery d = new Discovery("10.0.0.1", "aa:bb:cc:dd:ee:01", "host1", DiscoverySource.ARP, T1, null);
        service.upsert(d);

        var found = repo.findByIpAddress("10.0.0.1");
        assertThat(found).isPresent();
        assertThat(found.get().getMacAddress()).isEqualTo("aa:bb:cc:dd:ee:01");
        assertThat(found.get().getHostname()).isEqualTo("host1");
    }

    @Test
    void upsert_existingIp_updatesLastSeenOnly_preservesMacIfAlreadySet() {
        // Pre-seed with MAC already set
        Device seed = new Device(null, "10.0.0.2", null, "aa:bb:cc:dd:ee:ff", T1, T1);
        repo.save(seed);

        // Upsert with a different MAC — existing MAC must be preserved
        Discovery d = new Discovery("10.0.0.2", "11:22:33:44:55:66", null, DiscoverySource.ARP, T2, null);
        service.upsert(d);

        var found = repo.findByIpAddress("10.0.0.2").orElseThrow();
        assertThat(found.getMacAddress()).isEqualTo("aa:bb:cc:dd:ee:ff"); // unchanged
        assertThat(found.getLastSeen()).isEqualTo(T2);
    }

    @Test
    void upsert_existingIp_fillsMacIfPreviouslyNull() {
        Device seed = new Device(null, "10.0.0.3", null, null, T1, T1);
        repo.save(seed);

        Discovery d = new Discovery("10.0.0.3", "ca:fe:ba:be:00:01", null, DiscoverySource.ARP, T2, null);
        service.upsert(d);

        var found = repo.findByIpAddress("10.0.0.3").orElseThrow();
        assertThat(found.getMacAddress()).isEqualTo("ca:fe:ba:be:00:01");
    }

    @Test
    void upsert_existingIp_fillsHostnameIfPreviouslyNull() {
        Device seed = new Device(null, "10.0.0.4", null, null, T1, T1);
        repo.save(seed);

        Discovery d = new Discovery("10.0.0.4", null, "new-hostname", DiscoverySource.MDNS, T2, null);
        service.upsert(d);

        var found = repo.findByIpAddress("10.0.0.4").orElseThrow();
        assertThat(found.getHostname()).isEqualTo("new-hostname");
    }

    @Test
    void upsert_idempotent_sameInputTwice_oneRow() {
        Discovery d = new Discovery("10.0.0.5", "aa:00:00:00:00:05", null, DiscoverySource.ARP, T1, null);
        service.upsert(d);
        service.upsert(new Discovery("10.0.0.5", "aa:00:00:00:00:05", null, DiscoverySource.ARP, T2, null));

        assertThat(repo.count()).isEqualTo(1L);
        var found = repo.findByIpAddress("10.0.0.5").orElseThrow();
        assertThat(found.getLastSeen()).isEqualTo(T2);
    }

    @Test
    void upsert_newIp_setsDiscoveryScopeFromClassifier() {
        Discovery d = new Discovery("172.17.0.2", "aa:bb:cc:dd:ee:11", "docker-sibling", DiscoverySource.ARP, T1, null);
        service.upsert(d);

        var found = repo.findByIpAddress("172.17.0.2").orElseThrow();
        assertThat(found.getDiscoveryScope()).isEqualTo(DiscoveryScope.DOCKER_BRIDGE);
    }

    @Test
    void upsert_existingRow_preservesDiscoveryScope() {
        Device seed = new Device(null, "169.254.73.152", null, "aa:bb:cc:dd:ee:22", T1, T1);
        seed.setDiscoveryScope(DiscoveryScope.LINK_LOCAL);
        repo.save(seed);

        // Upsert with a brand-new MAC + hostname. Update path must NOT touch scope.
        Discovery d = new Discovery("169.254.73.152", "11:22:33:44:55:66", "renamed-host", DiscoverySource.ARP, T2, null);
        service.upsert(d);

        var found = repo.findByIpAddress("169.254.73.152").orElseThrow();
        assertThat(found.getDiscoveryScope()).isEqualTo(DiscoveryScope.LINK_LOCAL);
        assertThat(found.getLastSeen()).isEqualTo(T2); // sanity — upsert did fire
    }

    @Test
    void deviceLastSeenIfaceFieldPersists() {
        Device device = new Device(null, "10.0.6.1", "iface-host", "aa:bb:cc:dd:ee:60", T1, T1);
        device.setLastSeenIface("eth0");
        Device saved = repo.save(device);

        Device fetched = repo.findById(saved.getId()).orElseThrow();
        assertThat(fetched.getLastSeenIface()).isEqualTo("eth0");
    }

    @Test
    void nmapUpsertDoesNotClobberPriorArpIface() {
        // Seed an ARP-discovered device with iface "eth0"
        Device seed = new Device(null, "10.0.7.1", null, "aa:bb:cc:dd:ee:70", T1, T1);
        seed.setLastSeenIface("eth0");
        repo.save(seed);

        // NMAP-sourced rescan carries no iface (null) — must NOT overwrite the prior value.
        Discovery nmap = new Discovery("10.0.7.1", null, "nmap-hostname", DiscoverySource.NMAP_SCAN, T2, null);
        service.upsert(nmap);

        var after = repo.findByIpAddress("10.0.7.1").orElseThrow();
        assertThat(after.getLastSeenIface()).isEqualTo("eth0");
    }

    @Test
    void arpUpsertReplacesPriorIface() {
        // Seed with iface "eth0"
        Device seed = new Device(null, "10.0.7.2", null, "aa:bb:cc:dd:ee:71", T1, T1);
        seed.setLastSeenIface("eth0");
        repo.save(seed);

        // ARP rescan with a different iface — must overwrite (cable swap / reattach).
        Discovery arp = new Discovery("10.0.7.2", "aa:bb:cc:dd:ee:71", null, DiscoverySource.ARP, T2, "docker0");
        service.upsert(arp);

        var after = repo.findByIpAddress("10.0.7.2").orElseThrow();
        assertThat(after.getLastSeenIface()).isEqualTo("docker0");
    }

    @Test
    void upsert_newIp_setsLastSeenIfaceFromDiscovery() {
        Discovery d = new Discovery("10.0.7.3", "aa:bb:cc:dd:ee:72", null, DiscoverySource.ARP, T1, "wlan0");
        service.upsert(d);

        var found = repo.findByIpAddress("10.0.7.3").orElseThrow();
        assertThat(found.getLastSeenIface()).isEqualTo("wlan0");
    }

    /**
     * AC2 regression: a known IP with null MAC that is re-observed with a MAC via the
     * batch entry point must UPDATE in place (MAC backfilled), not INSERT a second row
     * and violate the {@code device_ip_unique} constraint.
     *
     * <p>On the pre-AC1 batch path this would throw a {@code DataIntegrityViolationException}
     * because the MAC-bearing discovery's IP was never added to {@code ipSet}, so the existing
     * row was missed and an INSERT was attempted. Post-AC1 the IP is always in {@code ipSet},
     * the row is found via the {@code existingByIp} fallback, and the UPDATE branch fires.
     */
    @Test
    void upsertAll_knownIpNullMac_reobservedWithMac_updatesInPlace_noConstraintCrash() {
        // Pre-seed a known IP with null MAC (common after a ping-sweep with no ARP response)
        Device seed = new Device(null, "10.0.9.1", null, null, T1, T1);
        repo.save(seed);

        // Re-observe the same IP WITH a MAC via the batch path
        service.upsertAll(List.of(new Discovery("10.0.9.1", "aa:bb:cc:dd:ee:99", null, DiscoverySource.ARP, T2, "eth0")));

        // Must be exactly one row — UPDATE, not INSERT
        assertThat(repo.count()).isEqualTo(1L);
        var found = repo.findByIpAddress("10.0.9.1").orElseThrow();
        assertThat(found.getMacAddress()).isEqualTo("aa:bb:cc:dd:ee:99");  // backfilled
        assertThat(found.getLastSeen()).isEqualTo(T2);
        assertThat(found.getLastSeenIface()).isEqualTo("eth0");
    }

    // ────────────────────────────────────────────────────────────────────────
    // AC2 — discoverySource persistence (single upsert + batch upsertAll)
    // ────────────────────────────────────────────────────────────────────────

    /** AC2: single upsert INSERT path persists the discovery source. */
    @Test
    void upsert_persistsSource_onInsert() {
        Discovery d = new Discovery("10.0.10.1", null, null, DiscoverySource.NMAP_SCAN, T1, null);
        service.upsert(d);

        var found = repo.findByIpAddress("10.0.10.1").orElseThrow();
        assertThat(found.getDiscoverySource()).isEqualTo(DiscoverySource.NMAP_SCAN);
    }

    /** AC2: single upsert UPDATE path overwrites prior discovery source (last-writer-wins). */
    @Test
    void upsert_overwritesSource_onUpdate() {
        // Seed with ARP source
        Discovery first = new Discovery("10.0.10.2", "aa:bb:cc:dd:ee:a2", null, DiscoverySource.ARP, T1, null);
        service.upsert(first);

        // Re-observe via NMAP_SCAN — source must be overwritten
        Discovery second = new Discovery("10.0.10.2", null, null, DiscoverySource.NMAP_SCAN, T2, null);
        service.upsert(second);

        var found = repo.findByIpAddress("10.0.10.2").orElseThrow();
        assertThat(found.getDiscoverySource()).isEqualTo(DiscoverySource.NMAP_SCAN);
        assertThat(found.getLastSeen()).isEqualTo(T2);
    }

    /**
     * AC2: batch upsertAll must set discoverySource on BOTH insert and update paths.
     *
     * <p>This test is the load-bearing guard for the upsertAll callsites. A missed
     * insert callsite causes the null assertion on the seeded device to fail; a missed
     * update callsite causes the NMAP_SCAN assertion to remain ARP.
     */
    @Test
    void upsertAll_persistsSource_coversInsertAndUpdate() {
        // Seed one existing device (will be updated via ARP)
        Device seed = new Device(null, "10.0.11.1", null, "aa:bb:cc:dd:ee:b1", T1, T1);
        repo.save(seed);

        // Batch: ARP observation of existing device (UPDATE path) + new device (INSERT path)
        List<Discovery> batch = List.of(
            new Discovery("10.0.11.1", "aa:bb:cc:dd:ee:b1", null, DiscoverySource.ARP, T2, "eth0"),
            new Discovery("10.0.11.2", null, null, DiscoverySource.NMAP_SCAN, T2, null)
        );
        service.upsertAll(batch);

        // Existing device — UPDATE path — source must be set to ARP
        var updated = repo.findByIpAddress("10.0.11.1").orElseThrow();
        assertThat(updated.getDiscoverySource()).isEqualTo(DiscoverySource.ARP);

        // New device — INSERT path — source must be NMAP_SCAN
        var inserted = repo.findByIpAddress("10.0.11.2").orElseThrow();
        assertThat(inserted.getDiscoverySource()).isEqualTo(DiscoverySource.NMAP_SCAN);
    }

    // ────────────────────────────────────────────────────────────────────────
    // upsertWithScope — explicit, classifier-overriding scope (Docker discovery)
    // ────────────────────────────────────────────────────────────────────────

    /**
     * INSERT path: the explicit scope is written verbatim, OVERRIDING the IP-range classifier.
     * {@code 172.18.0.2} would classify as DOCKER_BRIDGE, but an internal-only container must
     * be persisted HOME when the caller says so.
     */
    @Test
    void upsertWithScope_insert_usesExplicitScope_overridingClassifier() {
        Discovery d = new Discovery("172.18.0.2", null, "pingpay-db", DiscoverySource.DOCKER, T1, null);
        service.upsertWithScope(d, DiscoveryScope.HOME);

        var found = repo.findByIpAddress("172.18.0.2").orElseThrow();
        assertThat(found.getDiscoveryScope()).isEqualTo(DiscoveryScope.HOME);
        assertThat(found.getHostname()).isEqualTo("pingpay-db");
        assertThat(found.getDiscoverySource()).isEqualTo(DiscoverySource.DOCKER);
    }

    /**
     * UPDATE path: unlike {@link DeviceUpsertService#upsert}, the explicit scope IS written on
     * update — a container that begins publishing a port must flip HOME → DOCKER_BRIDGE in place.
     */
    @Test
    void upsertWithScope_update_overwritesScope() {
        // Seed the same IP as HOME (internal-only container)
        service.upsertWithScope(
            new Discovery("172.18.0.5", null, "svc", DiscoverySource.DOCKER, T1, null),
            DiscoveryScope.HOME);

        // Re-observe now publishing a port → DOCKER_BRIDGE
        service.upsertWithScope(
            new Discovery("172.18.0.5", null, "svc", DiscoverySource.DOCKER, T2, null),
            DiscoveryScope.DOCKER_BRIDGE);

        var found = repo.findByIpAddress("172.18.0.5").orElseThrow();
        assertThat(found.getDiscoveryScope()).isEqualTo(DiscoveryScope.DOCKER_BRIDGE);
        assertThat(found.getLastSeen()).isEqualTo(T2);
        assertThat(repo.count()).isEqualTo(1L); // idempotent — single row
    }

    /** UPDATE path: container name (hostname) is refreshed even when previously set. */
    @Test
    void upsertWithScope_update_refreshesHostname() {
        Device seed = new Device(null, "172.18.0.9", "old-name", null, T1, T1);
        seed.setDiscoveryScope(DiscoveryScope.HOME);
        repo.save(seed);

        service.upsertWithScope(
            new Discovery("172.18.0.9", null, "renamed-container", DiscoverySource.DOCKER, T2, null),
            DiscoveryScope.DOCKER_BRIDGE);

        var found = repo.findByIpAddress("172.18.0.9").orElseThrow();
        assertThat(found.getHostname()).isEqualTo("renamed-container");
    }

    // ────────────────────────────────────────────────────────────────────────
    // AC1 + AC2 — bridge-alias hostname filtering and hostname priority
    // ────────────────────────────────────────────────────────────────────────

    /**
     * AC1: a discovery observation carrying hostname "host.docker.internal" (the Docker bridge
     * gateway alias) must NOT be persisted as the device's hostname on INSERT.
     * The device should have a null hostname rather than the alias.
     */
    @Test
    void upsert_bridgeAliasHostname_notStoredOnInsert() {
        Discovery d = new Discovery("192.168.68.51", "aa:bb:cc:dd:ee:51",
            "host.docker.internal", DiscoverySource.MDNS, T1, null);
        service.upsert(d);

        var found = repo.findByIpAddress("192.168.68.51").orElseThrow();
        assertThat(found.getHostname())
            .as("bridge alias must never be stored as hostname")
            .isNull();
    }

    /**
     * AC1: bridge alias observation arriving on UPDATE must not overwrite a null hostname
     * with the alias.
     */
    @Test
    void upsert_bridgeAliasHostname_notStoredOnUpdate_whenCurrentIsNull() {
        Device seed = new Device(null, "192.168.68.51", null, null, T1, T1);
        repo.save(seed);

        Discovery d = new Discovery("192.168.68.51", null,
            "host.docker.internal", DiscoverySource.MDNS, T2, null);
        service.upsert(d);

        var found = repo.findByIpAddress("192.168.68.51").orElseThrow();
        assertThat(found.getHostname())
            .as("bridge alias must not fill a null hostname slot")
            .isNull();
    }

    /**
     * AC2: if a device was somehow seeded with the bridge alias as its hostname, a subsequent
     * observation carrying a real hostname must SUPERSEDE it (override-alias policy).
     */
    @Test
    void upsert_realHostname_supersedessStoredBridgeAlias() {
        Device seed = new Device(null, "192.168.68.51", "host.docker.internal", null, T1, T1);
        repo.save(seed);

        Discovery d = new Discovery("192.168.68.51", null,
            "operators-laptop", DiscoverySource.MDNS, T2, null);
        service.upsert(d);

        var found = repo.findByIpAddress("192.168.68.51").orElseThrow();
        assertThat(found.getHostname())
            .as("real hostname must supersede a stored bridge alias")
            .isEqualTo("operators-laptop");
    }

    /**
     * AC2: a real hostname already stored must NOT be overwritten by a later bridge-alias
     * observation.
     */
    @Test
    void upsert_bridgeAlias_doesNotOverwriteRealHostname() {
        Device seed = new Device(null, "192.168.68.51", "real-hostname", null, T1, T1);
        repo.save(seed);

        Discovery d = new Discovery("192.168.68.51", null,
            "host.docker.internal", DiscoverySource.MDNS, T2, null);
        service.upsert(d);

        var found = repo.findByIpAddress("192.168.68.51").orElseThrow();
        assertThat(found.getHostname())
            .as("real hostname must never be overwritten by a bridge alias")
            .isEqualTo("real-hostname");
    }

    /**
     * AC5(a): upsert sequence — bridge-alias arrives first, real hostname arrives second
     * → final hostname is the real one.
     */
    @Test
    void upsert_sequence_aliasFirst_thenRealHostname_finalIsReal() {
        // Step 1: ARP/mDNS observes bridge alias
        Discovery aliasObs = new Discovery("192.168.68.51", "aa:bb:cc:dd:ee:51",
            "host.docker.internal", DiscoverySource.MDNS, T1, null);
        service.upsert(aliasObs);

        // Step 2: mDNS later resolves the real hostname
        Discovery realObs = new Discovery("192.168.68.51", null,
            "operators-laptop.local", DiscoverySource.MDNS, T2, null);
        service.upsert(realObs);

        var found = repo.findByIpAddress("192.168.68.51").orElseThrow();
        assertThat(found.getHostname()).isEqualTo("operators-laptop.local");
    }

    /**
     * AC5(b): bridge-alias-only observation sequence — hostname stays null (never the alias).
     */
    @Test
    void upsert_bridgeAliasOnly_hostnameRemainsNull() {
        Discovery d1 = new Discovery("192.168.68.51", "aa:bb:cc:dd:ee:51",
            "host.docker.internal", DiscoverySource.ARP, T1, null);
        service.upsert(d1);

        Discovery d2 = new Discovery("192.168.68.51", null,
            "host.docker.internal", DiscoverySource.MDNS, T2, null);
        service.upsert(d2);

        var found = repo.findByIpAddress("192.168.68.51").orElseThrow();
        assertThat(found.getHostname())
            .as("after two alias-only observations, hostname must remain null")
            .isNull();
    }

    /**
     * AC2 (batch): upsertAll INSERT path must also filter the bridge alias.
     */
    @Test
    void upsertAll_bridgeAliasHostname_notStoredOnInsert() {
        service.upsertAll(List.of(new Discovery("192.168.68.51", "aa:bb:cc:dd:ee:51",
            "host.docker.internal", DiscoverySource.ARP, T1, null)));

        var found = repo.findByIpAddress("192.168.68.51").orElseThrow();
        assertThat(found.getHostname()).isNull();
    }

    /**
     * AC2 (batch): upsertAll UPDATE path must not let alias supersede a null or real hostname.
     */
    @Test
    void upsertAll_bridgeAliasHostname_notStoredOnUpdate() {
        Device seed = new Device(null, "192.168.68.51", null, null, T1, T1);
        repo.save(seed);

        service.upsertAll(List.of(new Discovery("192.168.68.51", null,
            "host.docker.internal", DiscoverySource.MDNS, T2, null)));

        var found = repo.findByIpAddress("192.168.68.51").orElseThrow();
        assertThat(found.getHostname()).isNull();
    }
}
