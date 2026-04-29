package io.castellum.domain;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@DataJpaTest
class ScanRepositoryTest {

    @Autowired
    private ScanRepository repository;

    @Test
    void saveWithDefaultStatus_returnsPending() {
        Scan scan = new Scan();
        scan.setCidr("192.168.1.0/24");
        scan.setScanType("PING_SWEEP");
        scan.setRequestedAt(Instant.now());

        Scan saved = repository.save(scan);
        Optional<Scan> found = repository.findById(saved.getId());

        assertTrue(found.isPresent());
        assertEquals(ScanStatus.PENDING, found.get().getStatus());
    }

    @Test
    void findByStatus_returnsInsertedRow() {
        Scan scan = new Scan();
        scan.setCidr("10.0.0.0/8");
        scan.setScanType("SERVICE_DETECT");
        scan.setRequestedAt(Instant.now());

        repository.save(scan);

        List<Scan> pending = repository.findByStatus(ScanStatus.PENDING);
        assertFalse(pending.isEmpty());
        assertTrue(pending.stream().anyMatch(s -> "10.0.0.0/8".equals(s.getCidr())));
    }
}
