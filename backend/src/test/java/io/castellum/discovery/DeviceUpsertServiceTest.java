package io.castellum.discovery;

import io.castellum.domain.Device;
import io.castellum.domain.DeviceRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.context.annotation.Import;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
@Import(DeviceUpsertService.class)
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
        Discovery d = new Discovery("10.0.0.1", "aa:bb:cc:dd:ee:01", "host1", DiscoverySource.ARP, T1);
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
        Discovery d = new Discovery("10.0.0.2", "11:22:33:44:55:66", null, DiscoverySource.ARP, T2);
        service.upsert(d);

        var found = repo.findByIpAddress("10.0.0.2").orElseThrow();
        assertThat(found.getMacAddress()).isEqualTo("aa:bb:cc:dd:ee:ff"); // unchanged
        assertThat(found.getLastSeen()).isEqualTo(T2);
    }

    @Test
    void upsert_existingIp_fillsMacIfPreviouslyNull() {
        Device seed = new Device(null, "10.0.0.3", null, null, T1, T1);
        repo.save(seed);

        Discovery d = new Discovery("10.0.0.3", "ca:fe:ba:be:00:01", null, DiscoverySource.ARP, T2);
        service.upsert(d);

        var found = repo.findByIpAddress("10.0.0.3").orElseThrow();
        assertThat(found.getMacAddress()).isEqualTo("ca:fe:ba:be:00:01");
    }

    @Test
    void upsert_existingIp_fillsHostnameIfPreviouslyNull() {
        Device seed = new Device(null, "10.0.0.4", null, null, T1, T1);
        repo.save(seed);

        Discovery d = new Discovery("10.0.0.4", null, "new-hostname", DiscoverySource.MDNS, T2);
        service.upsert(d);

        var found = repo.findByIpAddress("10.0.0.4").orElseThrow();
        assertThat(found.getHostname()).isEqualTo("new-hostname");
    }

    @Test
    void upsert_idempotent_sameInputTwice_oneRow() {
        Discovery d = new Discovery("10.0.0.5", "aa:00:00:00:00:05", null, DiscoverySource.ARP, T1);
        service.upsert(d);
        service.upsert(new Discovery("10.0.0.5", "aa:00:00:00:00:05", null, DiscoverySource.ARP, T2));

        assertThat(repo.count()).isEqualTo(1L);
        var found = repo.findByIpAddress("10.0.0.5").orElseThrow();
        assertThat(found.getLastSeen()).isEqualTo(T2);
    }
}
