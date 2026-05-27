package io.castellum.domain;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;

@DataJpaTest
class DeviceServiceCountJpaTest {

    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private DeviceRepository deviceRepository;

    @Autowired
    private NetworkServiceRepository serviceRepository;

    private Device createDevice(String ip) {
        Device d = new Device();
        d.setIpAddress(ip);
        d.setFirstSeen(Instant.now());
        d.setLastSeen(Instant.now());
        return deviceRepository.saveAndFlush(d);
    }

    @Test
    void serviceCount_reflectsPersistedServiceRows() {
        Device saved = createDevice("10.1.2.3");

        // Seed 2 service rows for this device; observed_at is NOT NULL.
        serviceRepository.saveAndFlush(
            new NetworkService(null, saved.getId(), 80,  "tcp", "http",  null, Instant.now()));
        serviceRepository.saveAndFlush(
            new NetworkService(null, saved.getId(), 443, "tcp", "https", null, Instant.now()));

        // @Formula is computed at entity-load time; clear the first-level cache
        // so a fresh SELECT runs the subquery.
        entityManager.clear();
        Device reloaded = deviceRepository.findById(saved.getId()).orElseThrow();
        assertEquals(2L, reloaded.getServiceCount());
    }

    @Test
    void serviceCount_isZeroForDeviceWithNoServices() {
        Device saved = createDevice("10.1.2.4");

        entityManager.clear();
        Device reloaded = deviceRepository.findById(saved.getId()).orElseThrow();
        assertEquals(0L, reloaded.getServiceCount());
    }
}
