package io.castellum.cve;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.context.TestPropertySource;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

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
