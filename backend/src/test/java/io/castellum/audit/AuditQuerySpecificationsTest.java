package io.castellum.audit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
class AuditQuerySpecificationsTest {

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
    void emptyFilter_returnsAllFive() {
        var spec = AuditQuerySpecifications.build(new AuditFilter(null, null, null, null, null));
        List<AuditLog> results = repository.findAll(spec);
        assertThat(results).hasSize(5);
    }

    @Test
    void actionFilter_filtersScanSubmit() {
        var spec = AuditQuerySpecifications.build(new AuditFilter(null, null, "SCAN_SUBMIT", null, null));
        List<AuditLog> results = repository.findAll(spec);
        assertThat(results).hasSize(2);
        assertThat(results).allMatch(r -> "SCAN_SUBMIT".equals(r.getAction()));
    }

    @Test
    void actorFilter_filtersBob() {
        var spec = AuditQuerySpecifications.build(new AuditFilter(null, null, null, "bob", null));
        List<AuditLog> results = repository.findAll(spec);
        assertThat(results).hasSize(2);
        assertThat(results).allMatch(r -> "bob".equals(r.getActor()));
    }

    @Test
    void sinceFilter_filtersFromMay3() {
        var spec = AuditQuerySpecifications.build(
            new AuditFilter(Instant.parse("2026-05-03T00:00:00Z"), null, null, null, null));
        List<AuditLog> results = repository.findAll(spec);
        assertThat(results).hasSize(3);
    }

    @Test
    void untilFilter_isExclusive() {
        var spec = AuditQuerySpecifications.build(
            new AuditFilter(null, Instant.parse("2026-05-03T00:00:00Z"), null, null, null));
        List<AuditLog> results = repository.findAll(spec);
        assertThat(results).hasSize(2);
        assertThat(results).allMatch(r -> r.getOccurredAt().isBefore(Instant.parse("2026-05-03T00:00:00Z")));
    }

    @Test
    void allFiveFieldsCombined() {
        var spec = AuditQuerySpecifications.build(new AuditFilter(
            Instant.parse("2026-05-01T00:00:00Z"),
            Instant.parse("2026-05-06T00:00:00Z"),
            "SCAN_SUBMIT", "alice", "scan"));
        List<AuditLog> results = repository.findAll(spec);
        assertThat(results).hasSize(1);
        assertThat(results.get(0).getAction()).isEqualTo("SCAN_SUBMIT");
        assertThat(results.get(0).getActor()).isEqualTo("alice");
    }

    @Test
    void blankStringTreatedAsMissing() {
        var spec = AuditQuerySpecifications.build(new AuditFilter(null, null, "", "", ""));
        List<AuditLog> results = repository.findAll(spec);
        assertThat(results).hasSize(5);
    }
}
