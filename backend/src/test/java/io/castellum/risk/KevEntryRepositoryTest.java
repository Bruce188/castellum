package io.castellum.risk;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.dao.DataIntegrityViolationException;

import java.time.Instant;
import java.time.LocalDate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DataJpaTest
class KevEntryRepositoryTest {

    @Autowired
    private KevEntryRepository repo;

    private KevEntry buildEntry(String cveId) {
        KevEntry e = new KevEntry();
        e.setCveId(cveId);
        e.setDateAdded(LocalDate.now());
        e.setIngestedAt(Instant.now());
        return e;
    }

    @Test
    void save_findByCveId_returnsRow() {
        repo.save(buildEntry("CVE-2020-15778"));
        assertThat(repo.findByCveId("CVE-2020-15778")).isPresent();
    }

    @Test
    void existsByCveId_trueWhenPresent_falseWhenAbsent() {
        repo.save(buildEntry("CVE-2020-15778"));
        assertThat(repo.existsByCveId("CVE-2020-15778")).isTrue();
        assertThat(repo.existsByCveId("CVE-9999-9999")).isFalse();
    }

    @Test
    void unique_cveId_violationOnDuplicate() {
        repo.save(buildEntry("CVE-2020-15778"));
        assertThatThrownBy(() -> {
            repo.save(buildEntry("CVE-2020-15778"));
            repo.flush();
        }).isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    void findMaxIngestedAt_returnsLatest() {
        Instant earlier = Instant.parse("2026-01-01T00:00:00Z");
        Instant later = Instant.parse("2026-04-29T00:00:00Z");
        KevEntry e1 = buildEntry("CVE-2020-15778");
        e1.setIngestedAt(earlier);
        repo.save(e1);
        KevEntry e2 = buildEntry("CVE-2021-44228");
        e2.setIngestedAt(later);
        repo.save(e2);
        assertThat(repo.findMaxIngestedAt()).hasValue(later);
    }
}
