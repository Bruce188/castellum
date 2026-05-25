package io.castellum.audit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
class AuditLogRepositorySpecTest {

    @Autowired
    private TestEntityManager em;

    @Autowired
    private AuditLogRepository repository;

    @BeforeEach
    void seed() {
        em.persist(new AuditLog(Instant.parse("2026-05-01T00:00:00Z"), "alice", "SCAN_SUBMIT", "scan", "1", null));
        em.persist(new AuditLog(Instant.parse("2026-05-02T00:00:00Z"), "alice", "DEVICE_CREATE", "device", "1", null));
        em.persist(new AuditLog(Instant.parse("2026-05-03T00:00:00Z"), "bob", "SCAN_SUBMIT", "scan", "2", null));
        em.persist(new AuditLog(Instant.parse("2026-05-04T00:00:00Z"), "bob", "DEVICE_UPDATE", "device", "1", null));
        em.persist(new AuditLog(Instant.parse("2026-05-05T00:00:00Z"), "alice", "RBAC_DENIED", "audit", null, null));
        em.flush();
    }

    @Test
    void findAll_withSpecAndPageable_returnsCorrectPage() {
        var spec = AuditQuerySpecifications.build(new AuditFilter(null, null, null, "alice", null));
        var pageable = PageRequest.of(0, 2, Sort.by(Sort.Direction.DESC, "occurredAt"));
        Page<AuditLog> page = repository.findAll(spec, pageable);

        assertThat(page.getTotalElements()).isEqualTo(3);
        assertThat(page.getContent()).hasSize(2);
        // Most recent alice rows first: row5 (May 5 RBAC_DENIED), row2 (May 2 DEVICE_CREATE)
        assertThat(page.getContent().get(0).getOccurredAt())
            .isEqualTo(Instant.parse("2026-05-05T00:00:00Z"));
        assertThat(page.getContent().get(1).getOccurredAt())
            .isEqualTo(Instant.parse("2026-05-02T00:00:00Z"));
    }

    @Test
    void count_withSpec_matchesFindAll() {
        var spec = AuditQuerySpecifications.build(new AuditFilter(null, null, null, "alice", null));
        long count = repository.count(spec);
        assertThat(count).isEqualTo(3);
    }
}
