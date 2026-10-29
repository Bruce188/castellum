package io.castellum.cve;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.PageRequest;
import org.springframework.test.context.TestPropertySource;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

@DataJpaTest
@TestPropertySource(properties = {
    "spring.flyway.enabled=true",
    "spring.flyway.locations=classpath:db/migration/h2",
    "spring.jpa.hibernate.ddl-auto=validate"
})
class CveRepositoryTest {

    @Autowired
    private CveRepository cveRepository;

    private Cve buildCve(String cveId) {
        Cve cve = new Cve();
        cve.setCveId(cveId);
        cve.setLastModified(Instant.now());
        cve.setRawJson("{}");
        cve.setFetchedAt(Instant.now());
        return cve;
    }

    @Test
    void save_andFindByCveId_returnsRow() {
        Cve saved = cveRepository.save(buildCve("CVE-2020-15778"));
        assertNotNull(saved.getId());

        Optional<Cve> found = cveRepository.findByCveId("CVE-2020-15778");
        assertTrue(found.isPresent());
        assertEquals("CVE-2020-15778", found.get().getCveId());
    }

    @Test
    void save_duplicateCveId_throwsDataIntegrityViolation() {
        cveRepository.save(buildCve("CVE-2020-15778"));
        assertThrows(DataIntegrityViolationException.class, () -> {
            cveRepository.saveAndFlush(buildCve("CVE-2020-15778"));
        });
    }

    private Cve buildScored(String cveId, String v31, String v30, String v2) {
        Cve cve = buildCve(cveId);
        if (v31 != null) cve.setCvssV31Score(new BigDecimal(v31));
        if (v30 != null) cve.setCvssV30Score(new BigDecimal(v30));
        if (v2 != null) cve.setCvssV2Score(new BigDecimal(v2));
        return cve;
    }

    @Test
    void findByIdIn_includesV30AndV2OnlyCves_orderedByCoalescedScoreDesc() {
        // Broadened fleet gate: a CVE scored only under v3.0 or v2 must still surface
        // (the old v3.1-only finder dropped them). Ordering uses the coalesced best score.
        Cve v31 = cveRepository.save(buildScored("CVE-2024-0031", "9.0", null, null));
        Cve v30 = cveRepository.save(buildScored("CVE-2024-0030", null, "8.0", null));
        Cve v2 = cveRepository.save(buildScored("CVE-2024-0002", null, null, "7.0"));
        Cve none = cveRepository.save(buildScored("CVE-2024-0000", null, null, null));

        Set<Long> ids = Set.of(v31.getId(), v30.getId(), v2.getId(), none.getId());
        List<Cve> result = cveRepository
            .findByIdInAndCvssV31ScoreIsNotNull(ids, PageRequest.of(0, 10))
            .getContent();

        // none (no score) excluded; the other three present in coalesced-DESC order.
        assertThat(result).extracting(Cve::getCveId)
            .containsExactly("CVE-2024-0031", "CVE-2024-0030", "CVE-2024-0002");
    }

    @Test
    void findByIdInGreaterThanEqual_comparesAgainstCoalescedScore() {
        // minScore floor must compare against the coalesced score, so a v2-only 7.0 is
        // excluded by a 7.5 floor while a v3.0-only 8.0 is kept.
        Cve v31 = cveRepository.save(buildScored("CVE-2024-0031", "9.0", null, null));
        Cve v30 = cveRepository.save(buildScored("CVE-2024-0030", null, "8.0", null));
        Cve v2 = cveRepository.save(buildScored("CVE-2024-0002", null, null, "7.0"));

        Set<Long> ids = Set.of(v31.getId(), v30.getId(), v2.getId());
        List<Cve> result = cveRepository
            .findByIdInAndCvssV31ScoreGreaterThanEqual(ids, new BigDecimal("7.5"), PageRequest.of(0, 10))
            .getContent();

        assertThat(result).extracting(Cve::getCveId)
            .containsExactly("CVE-2024-0031", "CVE-2024-0030");
    }

    @Test
    void findMaxLastModified_returnsLatestTimestamp() {
        Instant earlier = Instant.now().minus(10, ChronoUnit.MINUTES);
        Instant later = Instant.now();

        Cve cve1 = buildCve("CVE-2020-00001");
        cve1.setLastModified(earlier);
        cveRepository.save(cve1);

        Cve cve2 = buildCve("CVE-2020-00002");
        cve2.setLastModified(later);
        cveRepository.save(cve2);

        Optional<Instant> max = cveRepository.findMaxLastModified();
        assertTrue(max.isPresent());
        // Truncate to millis for comparison (DB may truncate nanoseconds)
        assertEquals(later.truncatedTo(ChronoUnit.MILLIS), max.get().truncatedTo(ChronoUnit.MILLIS));
    }
}
