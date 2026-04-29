package io.castellum.domain;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.dao.DataIntegrityViolationException;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@DataJpaTest
class DeviceRepositoryTest {

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
