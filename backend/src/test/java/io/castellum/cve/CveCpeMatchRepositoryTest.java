package io.castellum.cve;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.context.TestPropertySource;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@DataJpaTest
@TestPropertySource(properties = {
    "spring.flyway.enabled=true",
    "spring.flyway.locations=classpath:db/migration/h2",
    "spring.jpa.hibernate.ddl-auto=validate"
})
class CveCpeMatchRepositoryTest {

    @Autowired
    private CveRepository cveRepository;

    @Autowired
    private CveCpeMatchRepository cveCpeMatchRepository;

    private Cve saveCve(String cveId) {
        Cve cve = new Cve();
        cve.setCveId(cveId);
        cve.setLastModified(Instant.now());
        cve.setRawJson("{}");
        cve.setFetchedAt(Instant.now());
        return cveRepository.save(cve);
    }

    private CveCpeMatch saveMatch(Long cveFk, String uri, boolean vulnerable, String versionEndExcluding) {
        CveCpeMatch match = new CveCpeMatch();
        match.setCveFk(cveFk);
        match.setCpe23Uri(uri);
        match.setVulnerable(vulnerable);
        match.setVersionEndExcluding(versionEndExcluding);
        return cveCpeMatchRepository.save(match);
    }

    @Test
    void save_andFindByCpe23Uri_returnsRow() {
        Cve cve = saveCve("CVE-2020-15778");
        saveMatch(cve.getId(), "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", true, "8.4");

        List<CveCpeMatch> found = cveCpeMatchRepository.findByCpe23Uri("cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*");
        assertEquals(1, found.size());
        assertEquals("cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", found.get(0).getCpe23Uri());
        assertEquals("8.4", found.get(0).getVersionEndExcluding());
    }

    @Test
    void findByCpe23UriStartingWith_returnsMatchingRows() {
        Cve cve = saveCve("CVE-2020-15778");
        saveMatch(cve.getId(), "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", true, "8.4");

        List<CveCpeMatch> found = cveCpeMatchRepository.findByCpe23UriStartingWithOrderByIdAsc("cpe:2.3:a:openbsd:openssh:");
        assertEquals(1, found.size());
    }

    @Test
    void deleteParentCve_cascadesDeleteToMatchRows() {
        Cve cve = saveCve("CVE-2020-15778");
        saveMatch(cve.getId(), "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", true, "8.4");

        assertEquals(1, cveCpeMatchRepository.count());
        cveRepository.delete(cve);
        cveRepository.flush();
        assertEquals(0, cveCpeMatchRepository.count());
    }
}
