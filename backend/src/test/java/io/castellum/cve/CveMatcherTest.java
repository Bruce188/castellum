package io.castellum.cve;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.TestPropertySource;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@DataJpaTest
@Import({CveMatcher.class})
@TestPropertySource(properties = {
    "spring.flyway.enabled=true",
    "spring.flyway.locations=classpath:db/migration/h2",
    "spring.jpa.hibernate.ddl-auto=validate"
})
class CveMatcherTest {

    @Autowired
    CveMatcher matcher;

    @Autowired
    CveRepository cveRepository;

    @Autowired
    CveCpeMatchRepository cveCpeMatchRepository;

    private Cve saveCve(String cveId) {
        Cve cve = new Cve();
        cve.setCveId(cveId);
        cve.setLastModified(Instant.now());
        cve.setRawJson("{}");
        cve.setFetchedAt(Instant.now());
        return cveRepository.save(cve);
    }

    private CveCpeMatch saveMatch(Long cveFk, String cpe23Uri, boolean vulnerable,
                                   String vsi, String vse, String vei, String vee) {
        CveCpeMatch m = new CveCpeMatch();
        m.setCveFk(cveFk);
        m.setCpe23Uri(cpe23Uri);
        m.setVulnerable(vulnerable);
        m.setVersionStartIncluding(vsi);
        m.setVersionStartExcluding(vse);
        m.setVersionEndIncluding(vei);
        m.setVersionEndExcluding(vee);
        return cveCpeMatchRepository.save(m);
    }

    // AC#2 -- the primary acceptance test
    @Test
    void findVulnerable_openssh_8_2_returnsCve2020_15778() {
        Cve cve = saveCve("CVE-2020-15778");
        saveMatch(cve.getId(),
            "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
            true, null, null, null, "8.4");

        List<Cve> results = matcher.findVulnerable("cpe:2.3:a:openbsd:openssh:8.2:*:*:*:*:*:*:*");

        assertEquals(1, results.size(), "Expected exactly one CVE for openssh 8.2");
        assertEquals("CVE-2020-15778", results.get(0).getCveId());
    }

    @Test
    void findVulnerable_versionAtUpperBoundExcluding_doesNotMatch() {
        Cve cve = saveCve("CVE-2020-15778-X");
        saveMatch(cve.getId(),
            "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
            true, null, null, null, "8.4");

        List<Cve> results = matcher.findVulnerable("cpe:2.3:a:openbsd:openssh:8.4:*:*:*:*:*:*:*");
        assertTrue(results.isEmpty(), "8.4 is excluded and should not match");
    }

    @Test
    void findVulnerable_versionBelowLowerBoundIncluding_doesNotMatch() {
        Cve cve = saveCve("CVE-2020-BOUND-LOW");
        saveMatch(cve.getId(),
            "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
            true, "8.0", null, null, "8.4");

        List<Cve> results = matcher.findVulnerable("cpe:2.3:a:openbsd:openssh:7.9:*:*:*:*:*:*:*");
        assertTrue(results.isEmpty(), "7.9 is below versionStartIncluding=8.0");
    }

    @Test
    void findVulnerable_versionAtLowerBoundIncluding_matches() {
        Cve cve = saveCve("CVE-2020-BOUND-AT");
        saveMatch(cve.getId(),
            "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
            true, "8.0", null, null, "8.4");

        List<Cve> results = matcher.findVulnerable("cpe:2.3:a:openbsd:openssh:8.0:*:*:*:*:*:*:*");
        assertEquals(1, results.size(), "8.0 = versionStartIncluding should match");
    }

    @Test
    void findVulnerable_literalVersionMatch() {
        Cve cve = saveCve("CVE-2020-LITERAL");
        saveMatch(cve.getId(),
            "cpe:2.3:a:openbsd:openssh:8.2:*:*:*:*:*:*:*",
            true, null, null, null, null);

        List<Cve> hit = matcher.findVulnerable("cpe:2.3:a:openbsd:openssh:8.2:*:*:*:*:*:*:*");
        assertEquals(1, hit.size(), "literal 8.2 should match");

        List<Cve> miss = matcher.findVulnerable("cpe:2.3:a:openbsd:openssh:8.3:*:*:*:*:*:*:*");
        assertTrue(miss.isEmpty(), "literal 8.2 must not match 8.3");
    }

    @Test
    void findVulnerable_unrelatedProduct_doesNotMatch() {
        Cve cve = saveCve("CVE-2021-APACHE");
        saveMatch(cve.getId(),
            "cpe:2.3:a:apache:httpd:*:*:*:*:*:*:*:*",
            true, null, null, null, "2.4.60");

        List<Cve> results = matcher.findVulnerable("cpe:2.3:a:openbsd:openssh:8.2:*:*:*:*:*:*:*");
        assertTrue(results.isEmpty(), "openssh query must not return apache CVE");
    }

    @Test
    void findVulnerable_nonVulnerableMatchRowsAreSkipped() {
        Cve cve = saveCve("CVE-2020-NONVULN");
        saveMatch(cve.getId(),
            "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
            false, null, null, null, "8.4");

        List<Cve> results = matcher.findVulnerable("cpe:2.3:a:openbsd:openssh:8.2:*:*:*:*:*:*:*");
        assertTrue(results.isEmpty(), "Non-vulnerable match rows must be skipped");
    }

    @Test
    void parse_rejectsMalformedCpe() {
        assertThrows(IllegalArgumentException.class, () -> Cpe23.parse("not-a-cpe"),
            "Malformed CPE URI should throw IllegalArgumentException");
    }

    /**
     * NB-1 regression lock: when a CVE has two matching rows (one literal + one range),
     * findVulnerableWithEvidence must return the lowest-id row as evidence on every call.
     */
    @Test
    void findVulnerableWithEvidence_multipleMatchingRows_returnsDeterministicLowestIdRow() {
        Cve cve = saveCve("CVE-DETERM-1");

        // Row A — range match, inserted first (lower id)
        CveCpeMatch rowA = saveMatch(cve.getId(),
            "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
            true, "8.0", null, null, "9.0");

        // Row B — literal version match, inserted second (higher id)
        CveCpeMatch rowB = saveMatch(cve.getId(),
            "cpe:2.3:a:openbsd:openssh:8.2:*:*:*:*:*:*:*",
            true, null, null, null, null);

        String query = "cpe:2.3:a:openbsd:openssh:8.2:*:*:*:*:*:*:*";

        List<CveMatcher.MatchEvidence> first  = matcher.findVulnerableWithEvidence(query);
        List<CveMatcher.MatchEvidence> second = matcher.findVulnerableWithEvidence(query);

        assertEquals(1, first.size(), "exactly one CVE expected");
        assertEquals(1, second.size(), "exactly one CVE expected on second call");

        long evidenceIdFirst  = first.get(0).matchedRow().getId();
        long evidenceIdSecond = second.get(0).matchedRow().getId();

        assertEquals(evidenceIdFirst, evidenceIdSecond,
            "matched row must be the same (deterministic) across repeated calls");
        assertEquals(rowA.getId(), evidenceIdFirst,
            "lowest-id row (rowA) must win as evidence");
    }
}
