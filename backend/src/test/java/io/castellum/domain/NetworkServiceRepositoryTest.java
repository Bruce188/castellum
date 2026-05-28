package io.castellum.domain;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.dao.DataIntegrityViolationException;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@DataJpaTest
class NetworkServiceRepositoryTest {

    @Autowired
    private NetworkServiceRepository serviceRepository;

    @Autowired
    private DeviceRepository deviceRepository;

    private Device createDevice(String ip) {
        Device d = new Device();
        d.setIpAddress(ip);
        d.setFirstSeen(Instant.now());
        d.setLastSeen(Instant.now());
        return deviceRepository.save(d);
    }

    @Test
    void saveAndFindById_preservesPortAndProtocol() {
        Device device = createDevice("192.168.1.10");

        NetworkService svc = new NetworkService();
        svc.setDeviceId(device.getId());
        svc.setPort(443);
        svc.setProtocol("tcp");
        svc.setObservedAt(Instant.now());

        NetworkService saved = serviceRepository.save(svc);
        Optional<NetworkService> found = serviceRepository.findById(saved.getId());

        assertTrue(found.isPresent());
        assertEquals(443, found.get().getPort());
        assertEquals("tcp", found.get().getProtocol());
    }

    @Test
    void duplicateDevicePortProtocol_throwsDataIntegrityViolationException() {
        Device device = createDevice("192.168.1.11");

        NetworkService svc1 = new NetworkService();
        svc1.setDeviceId(device.getId());
        svc1.setPort(80);
        svc1.setProtocol("tcp");
        svc1.setObservedAt(Instant.now());
        serviceRepository.save(svc1);

        NetworkService svc2 = new NetworkService();
        svc2.setDeviceId(device.getId());
        svc2.setPort(80);
        svc2.setProtocol("tcp");
        svc2.setObservedAt(Instant.now());

        assertThrows(DataIntegrityViolationException.class, () -> serviceRepository.saveAndFlush(svc2));
    }

    @Test
    void findByDeviceId_returnsAssociatedServices() {
        // Verifies the device_id FK column is correctly stored and queryable.
        // ON DELETE CASCADE (V2__create_service.sql) is enforced in production Postgres;
        // in H2 test profile Flyway is disabled so only the JPA schema is present.
        Device device = createDevice("192.168.1.12");

        NetworkService svc = new NetworkService();
        svc.setDeviceId(device.getId());
        svc.setPort(22);
        svc.setProtocol("tcp");
        svc.setObservedAt(Instant.now());
        serviceRepository.save(svc);

        List<NetworkService> found = serviceRepository.findByDeviceId(device.getId());
        assertEquals(1, found.size());
        assertEquals(22, found.get(0).getPort());
    }

    private NetworkService saveService(Long deviceId, int port, String proto) {
        NetworkService svc = new NetworkService();
        svc.setDeviceId(deviceId);
        svc.setPort(port);
        svc.setProtocol(proto);
        svc.setObservedAt(Instant.now());
        return serviceRepository.save(svc);
    }

    @Test
    void findByDeviceIdIn_returnsServicesForAllGivenDevices_excludesOthers() {
        Device d1 = createDevice("10.1.0.1");
        Device d2 = createDevice("10.1.0.2");
        Device d3 = createDevice("10.1.0.3");
        saveService(d1.getId(), 22, "tcp");
        saveService(d1.getId(), 443, "tcp");
        saveService(d2.getId(), 502, "tcp");
        saveService(d3.getId(), 102, "tcp"); // must NOT appear

        List<NetworkService> found =
            serviceRepository.findByDeviceIdIn(List.of(d1.getId(), d2.getId()));

        assertEquals(3, found.size());
        assertTrue(found.stream().allMatch(s ->
            s.getDeviceId().equals(d1.getId()) || s.getDeviceId().equals(d2.getId())));
        assertTrue(found.stream().noneMatch(s -> s.getDeviceId().equals(d3.getId())));
    }
}
