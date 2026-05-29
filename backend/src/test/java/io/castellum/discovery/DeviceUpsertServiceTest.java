package io.castellum.discovery;

import io.castellum.domain.Device;
import io.castellum.domain.DeviceRepository;
import io.castellum.discovery.DeviceRole;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.context.annotation.Import;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
@Import({DeviceUpsertService.class, DiscoveryScopeClassifier.class, DeviceRoleClassifier.class})
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
        Discovery d = new Discovery("10.0.0.1", "aa:bb:cc:dd:ee:01", "host1", DiscoverySource.ARP, T1, null, false);
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
        Discovery d = new Discovery("10.0.0.2", "11:22:33:44:55:66", null, DiscoverySource.ARP, T2, null, false);
        service.upsert(d);

        var found = repo.findByIpAddress("10.0.0.2").orElseThrow();
        assertThat(found.getMacAddress()).isEqualTo("aa:bb:cc:dd:ee:ff"); // unchanged
        assertThat(found.getLastSeen()).isEqualTo(T2);
    }

    @Test
    void upsert_existingIp_fillsMacIfPreviouslyNull() {
        Device seed = new Device(null, "10.0.0.3", null, null, T1, T1);
        repo.save(seed);

        Discovery d = new Discovery("10.0.0.3", "ca:fe:ba:be:00:01", null, DiscoverySource.ARP, T2, null, false);
        service.upsert(d);

        var found = repo.findByIpAddress("10.0.0.3").orElseThrow();
        assertThat(found.getMacAddress()).isEqualTo("ca:fe:ba:be:00:01");
    }

    @Test
    void upsert_existingIp_fillsHostnameIfPreviouslyNull() {
        Device seed = new Device(null, "10.0.0.4", null, null, T1, T1);
        repo.save(seed);

        Discovery d = new Discovery("10.0.0.4", null, "new-hostname", DiscoverySource.MDNS, T2, null, false);
        service.upsert(d);

        var found = repo.findByIpAddress("10.0.0.4").orElseThrow();
        assertThat(found.getHostname()).isEqualTo("new-hostname");
    }

    @Test
    void upsert_idempotent_sameInputTwice_oneRow() {
        Discovery d = new Discovery("10.0.0.5", "aa:00:00:00:00:05", null, DiscoverySource.ARP, T1, null, false);
        service.upsert(d);
        service.upsert(new Discovery("10.0.0.5", "aa:00:00:00:00:05", null, DiscoverySource.ARP, T2, null, false));

        assertThat(repo.count()).isEqualTo(1L);
        var found = repo.findByIpAddress("10.0.0.5").orElseThrow();
        assertThat(found.getLastSeen()).isEqualTo(T2);
    }

    @Test
    void upsert_newIp_setsDiscoveryScopeFromClassifier() {
        Discovery d = new Discovery("172.17.0.2", "aa:bb:cc:dd:ee:11", "docker-sibling", DiscoverySource.ARP, T1, null, false);
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
        Discovery d = new Discovery("169.254.73.152", "11:22:33:44:55:66", "renamed-host", DiscoverySource.ARP, T2, null, false);
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
        Discovery nmap = new Discovery("10.0.7.1", null, "nmap-hostname", DiscoverySource.NMAP_SCAN, T2, null, false);
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
        Discovery arp = new Discovery("10.0.7.2", "aa:bb:cc:dd:ee:71", null, DiscoverySource.ARP, T2, "docker0", false);
        service.upsert(arp);

        var after = repo.findByIpAddress("10.0.7.2").orElseThrow();
        assertThat(after.getLastSeenIface()).isEqualTo("docker0");
    }

    @Test
    void upsert_newIp_setsLastSeenIfaceFromDiscovery() {
        Discovery d = new Discovery("10.0.7.3", "aa:bb:cc:dd:ee:72", null, DiscoverySource.ARP, T1, "wlan0", false);
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
        service.upsertAll(List.of(new Discovery("10.0.9.1", "aa:bb:cc:dd:ee:99", null, DiscoverySource.ARP, T2, "eth0", false)));

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
        Discovery d = new Discovery("10.0.10.1", null, null, DiscoverySource.NMAP_SCAN, T1, null, false);
        service.upsert(d);

        var found = repo.findByIpAddress("10.0.10.1").orElseThrow();
        assertThat(found.getDiscoverySource()).isEqualTo(DiscoverySource.NMAP_SCAN);
    }

    /** AC2: single upsert UPDATE path overwrites prior discovery source (last-writer-wins). */
    @Test
    void upsert_overwritesSource_onUpdate() {
        // Seed with ARP source
        Discovery first = new Discovery("10.0.10.2", "aa:bb:cc:dd:ee:a2", null, DiscoverySource.ARP, T1, null, false);
        service.upsert(first);

        // Re-observe via NMAP_SCAN — source must be overwritten
        Discovery second = new Discovery("10.0.10.2", null, null, DiscoverySource.NMAP_SCAN, T2, null, false);
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
            new Discovery("10.0.11.1", "aa:bb:cc:dd:ee:b1", null, DiscoverySource.ARP, T2, "eth0", false),
            new Discovery("10.0.11.2", null, null, DiscoverySource.NMAP_SCAN, T2, null, false)
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
        Discovery d = new Discovery("172.18.0.2", null, "pingpay-db", DiscoverySource.DOCKER, T1, null, false);
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
            new Discovery("172.18.0.5", null, "svc", DiscoverySource.DOCKER, T1, null, false),
            DiscoveryScope.HOME);

        // Re-observe now publishing a port → DOCKER_BRIDGE
        service.upsertWithScope(
            new Discovery("172.18.0.5", null, "svc", DiscoverySource.DOCKER, T2, null, false),
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
            new Discovery("172.18.0.9", null, "renamed-container", DiscoverySource.DOCKER, T2, null, false),
            DiscoveryScope.DOCKER_BRIDGE);

        var found = repo.findByIpAddress("172.18.0.9").orElseThrow();
        assertThat(found.getHostname()).isEqualTo("renamed-container");
    }

    // ── AC1: upsertWithScope sets os="Linux" for DOCKER_BRIDGE containers ─────────────────────

    /** INSERT path: upsertWithScope(DOCKER_BRIDGE) must set osName="Linux". */
    @Test
    void upsertWithScope_insert_setsOsLinuxForDockerBridge() {
        Discovery d = new Discovery("172.21.0.3", null, "pingpay-db-custom", DiscoverySource.DOCKER, T1, null, false);
        service.upsertWithScope(d, DiscoveryScope.DOCKER_BRIDGE);

        var found = repo.findByIpAddress("172.21.0.3").orElseThrow();
        assertThat(found.getOsName())
            .as("docker container insert must have osName='Linux'")
            .isEqualTo("Linux");
        assertThat(found.getDiscoveryScope()).isEqualTo(DiscoveryScope.DOCKER_BRIDGE);
    }

    /** UPDATE path: upsertWithScope(DOCKER_BRIDGE) must also set/refresh osName="Linux". */
    @Test
    void upsertWithScope_update_setsOsLinuxForDockerBridge() {
        // Seed with no os
        Device seed = new Device(null, "172.21.0.4", "svc", null, T1, T1);
        seed.setDiscoveryScope(DiscoveryScope.HOME);
        repo.save(seed);

        service.upsertWithScope(
            new Discovery("172.21.0.4", null, "svc", DiscoverySource.DOCKER, T2, null, false),
            DiscoveryScope.DOCKER_BRIDGE);

        var found = repo.findByIpAddress("172.21.0.4").orElseThrow();
        assertThat(found.getOsName())
            .as("docker container update must set osName='Linux'")
            .isEqualTo("Linux");
    }

    /**
     * UPDATE path: upsertWithScope(DOCKER_BRIDGE) must NOT overwrite a scan-derived OS name
     * (e.g. "Linux 5.15" set by an OS_FINGERPRINT nmap scan) with the generic "Linux" default.
     * Fill-when-null — mirrors mac/hostname semantics.
     */
    @Test
    void upsertWithScope_update_doesNotClobberScanDerivedOsName() {
        // Seed a DOCKER_BRIDGE container whose OS was enriched by a prior nmap fingerprint
        Device seed = new Device(null, "172.21.0.10", "enriched-svc", null, T1, T1);
        seed.setDiscoveryScope(DiscoveryScope.DOCKER_BRIDGE);
        seed.setOsName("Linux 5.15");
        repo.save(seed);

        // Docker sweep re-observes the same container
        service.upsertWithScope(
            new Discovery("172.21.0.10", null, "enriched-svc", DiscoverySource.DOCKER, T2, null, false),
            DiscoveryScope.DOCKER_BRIDGE);

        var found = repo.findByIpAddress("172.21.0.10").orElseThrow();
        assertThat(found.getOsName())
            .as("scan-derived OS must survive a docker re-sweep")
            .isEqualTo("Linux 5.15");
        assertThat(found.getLastSeen()).isEqualTo(T2); // sanity — upsert did run
    }

    /** HOME-scoped upsertWithScope (synthetic gateway) must NOT set osName. */
    @Test
    void upsertWithScope_home_doesNotSetOsName() {
        Discovery d = new Discovery("172.18.0.1", null, "docker-net:pingpay_default", DiscoverySource.DOCKER, T1, null, false);
        service.upsertWithScope(d, DiscoveryScope.HOME);

        var found = repo.findByIpAddress("172.18.0.1").orElseThrow();
        assertThat(found.getOsName())
            .as("HOME-scoped device (synthetic gateway) must not get osName='Linux'")
            .isNull();
    }

    // ── AC3: passive upsert does not downgrade DOCKER_BRIDGE scope ───────────────────────────

    /**
     * A device previously seeded as DOCKER_BRIDGE by Docker discovery must NOT have its
     * scope overwritten to HOME by a subsequent passive (ARP/NMAP) upsert.
     */
    @Test
    void upsert_doesNotDowngradeDockerBridgeScope() {
        // Seed as DOCKER_BRIDGE (as docker discovery would)
        service.upsertWithScope(
            new Discovery("172.21.0.3", null, "pingpay-db-custom", DiscoverySource.DOCKER, T1, null, false),
            DiscoveryScope.DOCKER_BRIDGE);

        // Passive ARP re-observes same IP — on 172.21.x classifier would return HOME
        service.upsert(new Discovery("172.21.0.3", "02:42:ac:15:00:03", null, DiscoverySource.ARP, T2, null, false));

        var found = repo.findByIpAddress("172.21.0.3").orElseThrow();
        assertThat(found.getDiscoveryScope())
            .as("passive ARP must not downgrade DOCKER_BRIDGE to HOME")
            .isEqualTo(DiscoveryScope.DOCKER_BRIDGE);
        assertThat(found.getLastSeen()).isEqualTo(T2); // sanity — upsert did run
    }

    /** Non-container HOME device: passive upsert still preserves HOME (regression guard). */
    @Test
    void upsert_homeScopedDevice_remainsHome_afterPassiveObservation() {
        // Seed a normal HOME device (e.g. router on 192.168.1.1)
        Device seed = new Device(null, "192.168.1.1", "router", "aa:bb:cc:dd:ee:01", T1, T1);
        seed.setDiscoveryScope(DiscoveryScope.HOME);
        repo.save(seed);

        service.upsert(new Discovery("192.168.1.1", "aa:bb:cc:dd:ee:01", "router", DiscoverySource.ARP, T2, null, false));

        var found = repo.findByIpAddress("192.168.1.1").orElseThrow();
        assertThat(found.getDiscoveryScope())
            .as("non-container HOME device must stay HOME")
            .isEqualTo(DiscoveryScope.HOME);
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
            "host.docker.internal", DiscoverySource.MDNS, T1, null, false);
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
            "host.docker.internal", DiscoverySource.MDNS, T2, null, false);
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
            "operators-laptop", DiscoverySource.MDNS, T2, null, false);
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
            "host.docker.internal", DiscoverySource.MDNS, T2, null, false);
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
            "host.docker.internal", DiscoverySource.MDNS, T1, null, false);
        service.upsert(aliasObs);

        // Step 2: mDNS later resolves the real hostname
        Discovery realObs = new Discovery("192.168.68.51", null,
            "operators-laptop.local", DiscoverySource.MDNS, T2, null, false);
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
            "host.docker.internal", DiscoverySource.ARP, T1, null, false);
        service.upsert(d1);

        Discovery d2 = new Discovery("192.168.68.51", null,
            "host.docker.internal", DiscoverySource.MDNS, T2, null, false);
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
            "host.docker.internal", DiscoverySource.ARP, T1, null, false)));

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
            "host.docker.internal", DiscoverySource.MDNS, T2, null, false)));

        var found = repo.findByIpAddress("192.168.68.51").orElseThrow();
        assertThat(found.getHostname()).isNull();
    }

    // ────────────────────────────────────────────────────────────────────────
    // T1.1 — publishesHostPort persistence via upsertWithScope (last-writer-wins)
    // ────────────────────────────────────────────────────────────────────────

    /**
     * INSERT path: upsertWithScope with publishesHostPort=true must persist true on the Device.
     * The DB column publishes_host_port (added in V24) must be written on insert.
     */
    @Test
    void upsertWithScope_insert_persistsPublishesHostPort_true() {
        Discovery d = new Discovery("172.18.0.20", null, "published-svc", DiscoverySource.DOCKER, T1, null, true);
        service.upsertWithScope(d, DiscoveryScope.DOCKER_BRIDGE);

        var found = repo.findByIpAddress("172.18.0.20").orElseThrow();
        assertThat(found.isPublishesHostPort())
            .as("INSERT with publishesHostPort=true must persist true")
            .isTrue();
    }

    /**
     * INSERT path: upsertWithScope with publishesHostPort=false must persist false on the Device.
     */
    @Test
    void upsertWithScope_insert_persistsPublishesHostPort_false() {
        Discovery d = new Discovery("172.18.0.21", null, "internal-svc", DiscoverySource.DOCKER, T1, null, false);
        service.upsertWithScope(d, DiscoveryScope.DOCKER_BRIDGE);

        var found = repo.findByIpAddress("172.18.0.21").orElseThrow();
        assertThat(found.isPublishesHostPort())
            .as("INSERT with publishesHostPort=false must persist false")
            .isFalse();
    }

    /**
     * UPDATE path: upsertWithScope with publishesHostPort=true must overwrite a previously-false
     * value (last-writer-wins — a container that starts publishing a host port must flip the flag).
     */
    @Test
    void upsertWithScope_update_overwritesPublishesHostPort_falseToTrue() {
        // First upsert — internal-only container (false)
        service.upsertWithScope(
            new Discovery("172.18.0.22", null, "svc", DiscoverySource.DOCKER, T1, null, false),
            DiscoveryScope.DOCKER_BRIDGE);
        assertThat(repo.findByIpAddress("172.18.0.22").orElseThrow().isPublishesHostPort()).isFalse();

        // Second upsert — container now publishes a host port (true) — must overwrite
        service.upsertWithScope(
            new Discovery("172.18.0.22", null, "svc", DiscoverySource.DOCKER, T2, null, true),
            DiscoveryScope.DOCKER_BRIDGE);

        var found = repo.findByIpAddress("172.18.0.22").orElseThrow();
        assertThat(found.isPublishesHostPort())
            .as("UPDATE must flip publishesHostPort false→true (last-writer-wins)")
            .isTrue();
        assertThat(repo.count()).isEqualTo(1L); // still a single row
    }

    /**
     * UPDATE path: last-writer-wins — a subsequent upsert with publishesHostPort=false must
     * overwrite a previously-true value (port unpublished between sweeps).
     */
    @Test
    void upsertWithScope_update_overwritesPublishesHostPort_trueToFalse() {
        // First upsert — published container (true)
        service.upsertWithScope(
            new Discovery("172.18.0.23", null, "svc", DiscoverySource.DOCKER, T1, null, true),
            DiscoveryScope.DOCKER_BRIDGE);

        // Second upsert — port no longer published (false)
        service.upsertWithScope(
            new Discovery("172.18.0.23", null, "svc", DiscoverySource.DOCKER, T2, null, false),
            DiscoveryScope.DOCKER_BRIDGE);

        var found = repo.findByIpAddress("172.18.0.23").orElseThrow();
        assertThat(found.isPublishesHostPort())
            .as("UPDATE must flip publishesHostPort true→false (last-writer-wins)")
            .isFalse();
    }

    // ────────────────────────────────────────────────────────────────────────
    // Task 1.2 — scan attribution upsert overload
    // ────────────────────────────────────────────────────────────────────────

    /**
     * (1) Scan INSERT: upsert(d, 5L) on a new IP must set BOTH discoveredByScanId=5 AND
     * lastSeenByScanId=5 on the persisted device.
     */
    @Test
    void upsertForScan_insert_setsDiscoveredAndLastSeenScanId() {
        Discovery d = new Discovery("10.1.0.1", "aa:bb:cc:dd:01:01", "host-scan1",
            DiscoverySource.NMAP_SCAN, T1, null, false);

        service.upsert(d, 5L);

        var found = repo.findByIpAddress("10.1.0.1").orElseThrow();
        assertThat(found.getDiscoveredByScanId())
            .as("INSERT: discoveredByScanId must be set to the scan id")
            .isEqualTo(5L);
        assertThat(found.getLastSeenByScanId())
            .as("INSERT: lastSeenByScanId must be set to the scan id")
            .isEqualTo(5L);
    }

    /**
     * (2) Scan UPDATE: first upsert(d, 5L) seeds the device; second upsert(sameIp, 9L) must
     * update lastSeenByScanId to 9 but NEVER overwrite the original discoveredByScanId=5
     * (insert-once / sticky first-discovery).
     */
    @Test
    void upsertForScan_update_setsOnlyLastSeenScanId() {
        Discovery first = new Discovery("10.1.0.2", "aa:bb:cc:dd:01:02", "host-scan2",
            DiscoverySource.NMAP_SCAN, T1, null, false);
        service.upsert(first, 5L);

        // Re-observe same IP under a different scan
        Discovery second = new Discovery("10.1.0.2", "aa:bb:cc:dd:01:02", "host-scan2",
            DiscoverySource.NMAP_SCAN, T2, null, false);
        service.upsert(second, 9L);

        var found = repo.findByIpAddress("10.1.0.2").orElseThrow();
        assertThat(found.getDiscoveredByScanId())
            .as("UPDATE: discoveredByScanId must remain 5 (insert-once, first-discovery is sticky)")
            .isEqualTo(5L);
        assertThat(found.getLastSeenByScanId())
            .as("UPDATE: lastSeenByScanId must be updated to 9 (last-writer-wins)")
            .isEqualTo(9L);
        assertThat(repo.count()).isEqualTo(1L); // single row — no duplicate
    }

    /**
     * (3) Non-scan delegate: plain upsert(d) and explicit upsert(d, null) must leave BOTH
     * attribution columns NULL — non-scan callers (docker/passive/ARP) are unaffected.
     */
    @Test
    void upsert_nonScanDelegate_leavesAttributionNull() {
        // plain upsert(d) — the existing public API used by docker/passive/ARP
        Discovery d1 = new Discovery("10.1.0.3", "aa:bb:cc:dd:01:03", "host-nonscan1",
            DiscoverySource.ARP, T1, null, false);
        service.upsert(d1);

        var found1 = repo.findByIpAddress("10.1.0.3").orElseThrow();
        assertThat(found1.getDiscoveredByScanId())
            .as("plain upsert(d): discoveredByScanId must remain null")
            .isNull();
        assertThat(found1.getLastSeenByScanId())
            .as("plain upsert(d): lastSeenByScanId must remain null")
            .isNull();

        // explicit upsert(d, null) — must also write no attribution
        Discovery d2 = new Discovery("10.1.0.4", "aa:bb:cc:dd:01:04", "host-nonscan2",
            DiscoverySource.ARP, T1, null, false);
        service.upsert(d2, null);

        var found2 = repo.findByIpAddress("10.1.0.4").orElseThrow();
        assertThat(found2.getDiscoveredByScanId())
            .as("upsert(d, null): discoveredByScanId must remain null")
            .isNull();
        assertThat(found2.getLastSeenByScanId())
            .as("upsert(d, null): lastSeenByScanId must remain null")
            .isNull();
    }

    // ────────────────────────────────────────────────────────────────────────
    // N2 — non-scan paths leave scan attribution columns NULL
    // ────────────────────────────────────────────────────────────────────────

    /**
     * N2(a): {@code upsertWithScope} is a Docker/scope-explicit path — it must NEVER set
     * {@code discoveredByScanId} or {@code lastSeenByScanId}. Both columns must remain null
     * after insert and after update.
     */
    @Test
    void upsertWithScope_leavesAttributionNull() {
        // INSERT path
        Discovery d1 = new Discovery("10.5.0.1", null, "svc-a", DiscoverySource.DOCKER, T1, null, false);
        Device inserted = service.upsertWithScope(d1, DiscoveryScope.HOME);

        assertThat(inserted.getDiscoveredByScanId())
            .as("upsertWithScope INSERT: discoveredByScanId must be null (non-scan path)")
            .isNull();
        assertThat(inserted.getLastSeenByScanId())
            .as("upsertWithScope INSERT: lastSeenByScanId must be null (non-scan path)")
            .isNull();

        // UPDATE path — re-observe the same device
        Discovery d2 = new Discovery("10.5.0.1", null, "svc-a", DiscoverySource.DOCKER, T2, null, false);
        Device updated = service.upsertWithScope(d2, DiscoveryScope.DOCKER_BRIDGE);

        assertThat(updated.getDiscoveredByScanId())
            .as("upsertWithScope UPDATE: discoveredByScanId must remain null (non-scan path)")
            .isNull();
        assertThat(updated.getLastSeenByScanId())
            .as("upsertWithScope UPDATE: lastSeenByScanId must remain null (non-scan path)")
            .isNull();
        assertThat(repo.count()).isEqualTo(1L);
    }

    /**
     * N2(b): {@code upsertAll} (batch passive/ARP) is a non-scan path — it must NEVER set
     * {@code discoveredByScanId} or {@code lastSeenByScanId}. Covers both the INSERT and
     * UPDATE branches inside the batch method.
     */
    @Test
    void upsertAll_leavesAttributionNull() {
        // Seed one device so one slot goes through the UPDATE branch
        Device seed = new Device(null, "10.5.1.1", null, "aa:bb:cc:dd:e0:01", T1, T1);
        repo.save(seed);

        List<Discovery> batch = List.of(
            // UPDATE branch — known IP
            new Discovery("10.5.1.1", "aa:bb:cc:dd:e0:01", null, DiscoverySource.ARP, T2, "eth0", false),
            // INSERT branch — new IP
            new Discovery("10.5.1.2", "aa:bb:cc:dd:e0:02", null, DiscoverySource.ARP, T2, null, false)
        );
        List<Device> results = service.upsertAll(batch);

        assertThat(results).hasSize(2);
        for (Device d : results) {
            assertThat(d.getDiscoveredByScanId())
                .as("upsertAll: discoveredByScanId must be null for ip=%s", d.getIpAddress())
                .isNull();
            assertThat(d.getLastSeenByScanId())
                .as("upsertAll: lastSeenByScanId must be null for ip=%s", d.getIpAddress())
                .isNull();
        }
    }

    // ────────────────────────────────────────────────────────────────────────
    // Task 1.1 — DeviceRole default round-trip (entity column + default)
    // ────────────────────────────────────────────────────────────────────────

    /**
     * A freshly upserted plain ARP device (no OS, no docker source) must persist and
     * reload with getDeviceRole() == UNKNOWN. This verifies the entity column + default
     * round-trip via Hibernate-generated schema (Flyway disabled in unit test profile).
     * DeviceRoleClassifier is NOT in @Import here — classifier wiring is Task 2.1.
     */
    @Test
    void upsert_newIp_defaultsDeviceRoleUnknown_whenNoSignal() {
        Discovery d = new Discovery("10.0.0.99", "aa:bb:cc:dd:ee:99", "plainhost",
            DiscoverySource.ARP, T1, null, false);
        service.upsert(d);

        var found = repo.findByIpAddress("10.0.0.99").orElseThrow();
        assertThat(found.getDeviceRole()).isEqualTo(DeviceRole.UNKNOWN);
    }

    // ────────────────────────────────────────────────────────────────────────
    // Task 2.1 — DeviceRoleClassifier wiring (all six upsert branches)
    // ────────────────────────────────────────────────────────────────────────

    /**
     * INSERT + UPDATE paths via upsertWithScope: a Docker container (source=DOCKER,
     * hostname not "docker-net:*") must be classified as CONTAINER on both insert and update.
     */
    @Test
    void upsertWithScope_dockerContainer_setsContainerRole() {
        service.upsertWithScope(
            new Discovery("172.20.0.5", null, "api-1", DiscoverySource.DOCKER, T1, null, false),
            DiscoveryScope.DOCKER_BRIDGE);

        var found = repo.findByIpAddress("172.20.0.5").orElseThrow();
        assertThat(found.getDeviceRole())
            .as("INSERT via upsertWithScope (DOCKER, real hostname) must classify CONTAINER")
            .isEqualTo(DeviceRole.CONTAINER);

        // Re-upsert (UPDATE branch) — must still be CONTAINER
        service.upsertWithScope(
            new Discovery("172.20.0.5", null, "api-1", DiscoverySource.DOCKER, T2, null, false),
            DiscoveryScope.DOCKER_BRIDGE);

        var updated = repo.findByIpAddress("172.20.0.5").orElseThrow();
        assertThat(updated.getDeviceRole())
            .as("UPDATE via upsertWithScope must preserve CONTAINER role")
            .isEqualTo(DeviceRole.CONTAINER);
    }

    /**
     * A docker-net synthetic gateway (source=DOCKER, hostname starts with "docker-net:")
     * must stay UNKNOWN on both insert and update (docker-net gateway rule fires first).
     */
    @Test
    void upsertWithScope_dockerNetGateway_staysUnknown() {
        service.upsertWithScope(
            new Discovery("172.20.0.1", null, "docker-net:supabase", DiscoverySource.DOCKER, T1, null, false),
            DiscoveryScope.DOCKER_BRIDGE);

        var found = repo.findByIpAddress("172.20.0.1").orElseThrow();
        assertThat(found.getDeviceRole())
            .as("docker-net gateway must stay UNKNOWN")
            .isEqualTo(DeviceRole.UNKNOWN);
    }

    /**
     * upsert(Discovery, Long) scan path: INSERT and UPDATE branches both classify and persist role.
     * Seed a device via a first scan upsert (ARP, no OS → UNKNOWN), then re-seed with an OS-bearing
     * discovery that should flip to SERVER (update branch classification).
     */
    @Test
    void upsert_scanPath_setsRoleFromSignals() {
        // INSERT path — plain ARP with no OS signals → UNKNOWN (use .5 to avoid .1 ROUTER rule)
        Discovery insert = new Discovery("10.50.0.5", "aa:bb:cc:00:50:05", "server-host",
            DiscoverySource.NMAP_SCAN, T1, null, false);
        service.upsert(insert, 1L);

        var afterInsert = repo.findByIpAddress("10.50.0.5").orElseThrow();
        assertThat(afterInsert.getDeviceRole())
            .as("INSERT: no OS signal → UNKNOWN")
            .isEqualTo(DeviceRole.UNKNOWN);

        // Pre-set osName on the stored device so the UPDATE branch sees a server OS
        afterInsert.setOsName("Windows Server 2019");
        repo.save(afterInsert);

        // UPDATE path — re-upsert, classifier reads the now-set osName → SERVER
        Discovery update = new Discovery("10.50.0.5", "aa:bb:cc:00:50:05", "server-host",
            DiscoverySource.NMAP_SCAN, T2, null, false);
        service.upsert(update, 2L);

        var afterUpdate = repo.findByIpAddress("10.50.0.5").orElseThrow();
        assertThat(afterUpdate.getDeviceRole())
            .as("UPDATE: server OS on device → SERVER")
            .isEqualTo(DeviceRole.SERVER);
    }

    /**
     * upsertAll batch: INSERT and UPDATE branches both classify and persist role.
     * One brand-new Docker container (INSERT → CONTAINER) + one pre-seeded HOME device (UPDATE).
     */
    @Test
    void upsertAll_batch_setsRoleOnInsertAndUpdate() {
        // Seed one existing device (will take the UPDATE branch); use .5 to avoid .1 ROUTER rule
        Device seed = new Device(null, "10.51.0.5", null, "aa:bb:cc:00:51:05", T1, T1);
        repo.save(seed);

        List<Discovery> batch = List.of(
            // UPDATE branch — ARP, no OS → UNKNOWN (no downgrade from existing UNKNOWN is a no-op)
            new Discovery("10.51.0.5", "aa:bb:cc:00:51:05", null, DiscoverySource.ARP, T2, null, false),
            // INSERT branch — Docker container → CONTAINER
            new Discovery("172.20.0.7", null, "db-1", DiscoverySource.DOCKER, T2, null, false)
        );
        service.upsertAll(batch);

        var updated = repo.findByIpAddress("10.51.0.5").orElseThrow();
        assertThat(updated.getDeviceRole())
            .as("UPDATE batch path: ARP no-OS → UNKNOWN")
            .isEqualTo(DeviceRole.UNKNOWN);

        var inserted = repo.findByIpAddress("172.20.0.7").orElseThrow();
        assertThat(inserted.getDeviceRole())
            .as("INSERT batch path: DOCKER container → CONTAINER")
            .isEqualTo(DeviceRole.CONTAINER);
    }

    /**
     * Non-downgrade guard: a device once classified as CONTAINER (Docker source) must NOT
     * have its role overwritten back to UNKNOWN by a subsequent signal-less ARP re-sweep
     * that the classifier would classify as UNKNOWN.
     */
    @Test
    void upsert_nonDowngrade_knownRoleSurvivesSignallessResweep() {
        // Step 1: seed as Docker container → CONTAINER
        service.upsertWithScope(
            new Discovery("172.20.0.9", null, "redis-1", DiscoverySource.DOCKER, T1, null, false),
            DiscoveryScope.DOCKER_BRIDGE);

        var afterSeed = repo.findByIpAddress("172.20.0.9").orElseThrow();
        assertThat(afterSeed.getDeviceRole()).isEqualTo(DeviceRole.CONTAINER);

        // Step 2: re-upsert via a signal-less ARP sweep that would classify UNKNOWN
        // (source=ARP, no OS, non-.1 ip → classifier returns UNKNOWN)
        service.upsert(new Discovery("172.20.0.9", "02:42:ac:14:00:09", null,
            DiscoverySource.ARP, T2, null, false));

        var afterResweep = repo.findByIpAddress("172.20.0.9").orElseThrow();
        assertThat(afterResweep.getDeviceRole())
            .as("non-downgrade guard: known CONTAINER must survive a signal-less ARP re-sweep")
            .isEqualTo(DeviceRole.CONTAINER);
    }

    // ────────────────────────────────────────────────────────────────────────
    // Task 1.2 — repository attribution queries
    // ────────────────────────────────────────────────────────────────────────

    /**
     * findIdsByDiscoveredByScanId(5L) returns only the device attributed to scan 5 on INSERT.
     * The device re-observed by scan 9 must NOT appear (its discoveredByScanId is still 5,
     * but this test verifies the query is keyed to the correct column).
     *
     * Additionally:
     * - findIdsByLastSeenByScanId(9L) must return BOTH the device first-seen by scan 5 (now
     *   re-observed by scan 9) AND a brand-new device inserted by scan 9.
     * - findByLastSeenByScanId(9L) must return the same two rows as full Device entities.
     */
    @Test
    void repositoryAttributionQueries_returnCorrectSets() {
        // Device A: discovered by scan 5, then re-observed by scan 9
        Discovery dA1 = new Discovery("10.2.0.1", "aa:bb:cc:dd:02:01", "device-a",
            DiscoverySource.NMAP_SCAN, T1, null, false);
        Device deviceA = service.upsert(dA1, 5L);
        Discovery dA2 = new Discovery("10.2.0.1", "aa:bb:cc:dd:02:01", "device-a",
            DiscoverySource.NMAP_SCAN, T2, null, false);
        service.upsert(dA2, 9L);

        // Device B: brand-new device inserted by scan 9
        Discovery dB = new Discovery("10.2.0.2", "aa:bb:cc:dd:02:02", "device-b",
            DiscoverySource.NMAP_SCAN, T2, null, false);
        Device deviceB = service.upsert(dB, 9L);

        // findIdsByDiscoveredByScanId(5L) → only device A (inserted by scan 5)
        List<Long> discoveredByScan5 = repo.findIdsByDiscoveredByScanId(5L);
        assertThat(discoveredByScan5)
            .as("findIdsByDiscoveredByScanId(5) must return only the device first seen by scan 5")
            .containsExactlyInAnyOrder(deviceA.getId());

        // findIdsByDiscoveredByScanId(9L) → only device B (inserted by scan 9)
        List<Long> discoveredByScan9 = repo.findIdsByDiscoveredByScanId(9L);
        assertThat(discoveredByScan9)
            .as("findIdsByDiscoveredByScanId(9) must return only the device first seen by scan 9")
            .containsExactlyInAnyOrder(deviceB.getId());

        // findIdsByLastSeenByScanId(9L) → both device A (re-observed) and device B (new)
        List<Long> lastSeenByScan9 = repo.findIdsByLastSeenByScanId(9L);
        assertThat(lastSeenByScan9)
            .as("findIdsByLastSeenByScanId(9) must return both devices last observed by scan 9")
            .containsExactlyInAnyOrder(deviceA.getId(), deviceB.getId());

        // findByLastSeenByScanId(9L) → same two rows as full entities
        List<io.castellum.domain.Device> lastSeenEntities = repo.findByLastSeenByScanId(9L);
        assertThat(lastSeenEntities)
            .as("findByLastSeenByScanId(9) must return the two Device entities for scan 9")
            .extracting(io.castellum.domain.Device::getId)
            .containsExactlyInAnyOrder(deviceA.getId(), deviceB.getId());
    }
}
