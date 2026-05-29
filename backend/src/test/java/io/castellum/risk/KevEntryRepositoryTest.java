package io.castellum.risk;

import io.castellum.cve.Cve;
import io.castellum.cve.CveRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.context.TestPropertySource;

import java.time.Instant;
import java.time.LocalDate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DataJpaTest
@TestPropertySource(properties = {
    "spring.flyway.enabled=true",
    "spring.flyway.locations=classpath:db/migration/h2",
    "spring.jpa.hibernate.ddl-auto=validate"
})
class KevEntryRepositoryTest {

    @Autowired
    private KevEntryRepository repo;

    @Autowired
    private CveRepository cveRepository;

    private KevEntry buildEntry(String cveId) {
        KevEntry e = new KevEntry();
        e.setCveId(cveId);
        e.setDateAdded(LocalDate.now());
        e.setIngestedAt(Instant.now());
        return e;
    }

    private Cve buildCve(String cveId) {
        Cve cve = new Cve();
        cve.setCveId(cveId);
        cve.setLastModified(Instant.now());
        cve.setRawJson("{}");
        cve.setFetchedAt(Instant.now());
        return cve;
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

    /**
     * N-1: countKevInCorpus returns corpus∩KEV size.
     * Seeds 3 CVEs in corpus and 4 KEV entries (3 overlap, 1 KEV-only).
     * Expects count = 3.
     */
    @Test
    void countKevInCorpus_returnsOverlapCount() {
        // Corpus: 3 CVEs present
        cveRepository.save(buildCve("CVE-2020-15778"));
        cveRepository.save(buildCve("CVE-2021-44228"));
        cveRepository.save(buildCve("CVE-2022-22965"));

        // KEV catalog: 3 matching corpus + 1 KEV-only (not in corpus)
        repo.save(buildEntry("CVE-2020-15778"));
        repo.save(buildEntry("CVE-2021-44228"));
        repo.save(buildEntry("CVE-2022-22965"));
        repo.save(buildEntry("CVE-2019-99999")); // KEV-only, not in corpus

        assertThat(repo.countKevInCorpus()).isEqualTo(3L);
    }

    @Test
    void countKevInCorpus_returnsZeroWhenNoOverlap() {
        // Corpus CVE present, but KEV catalog has a different CVE
        cveRepository.save(buildCve("CVE-2020-15778"));
        repo.save(buildEntry("CVE-2021-99999"));

        assertThat(repo.countKevInCorpus()).isEqualTo(0L);
    }
}
