package io.castellum.cve;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.TestPropertySource;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

/**
 * AC2 — version-divergence regression lock.
 *
 * <p>Fixtures model the live-shape observed on 2026-05-29:
 * <ul>
 *   <li>postgres 15 matches a dedicated pg-15-only CVE (range: [15.0, 16.0))</li>
 *   <li>postgres 16 matches a shared CVE (range: [14.0, 17.0)) + a pg-16-specific CVE (range: [16.0, 17.0))</li>
 *   <li>postgres 17 matches the shared CVE + a pg-17-only CVE (range: [17.0, 18.0))</li>
 * </ul>
 *
 * <p>This mirrors the live observation: castellum-pg (pg16) and supabase_db (pg17.6)
 * share 9 CVEs but pg17 also matched CVE-2026-6476 (17.x only). Version-aware
 * divergence is the correct behaviour — this test guards against regression to wildcard matching.
 */
@DataJpaTest
@Import({CveMatcher.class})
@TestPropertySource(properties = {
    "spring.flyway.enabled=true",
    "spring.flyway.locations=classpath:db/migration/h2",
    "spring.jpa.hibernate.ddl-auto=validate"
})
class CveMatcherVersionDivergenceTest {

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

    private void saveMatch(Long cveFk, String cpe23Uri, boolean vulnerable,
                           String vsi, String vse, String vei, String vee) {
        CveCpeMatch m = new CveCpeMatch();
        m.setCveFk(cveFk);
        m.setCpe23Uri(cpe23Uri);
        m.setVulnerable(vulnerable);
        m.setVersionStartIncluding(vsi);
        m.setVersionStartExcluding(vse);
        m.setVersionEndIncluding(vei);
        m.setVersionEndExcluding(vee);
        cveCpeMatchRepository.save(m);
    }

    /**
     * Three postgres versions produce DIFFERENT matched-CVE sets.
     * Shared CVE matches all three; major-specific CVEs match only one.
     * Proves matching is not version-less and that two same-product devices
     * sharing most CVEs is explained by matching semantics, not a bug.
     */
    @Test
    void postgres_15_16_17_produceDivergentMatchedSets() {
        // Shared CVE — affects pg 14.0 ≤ v < 17.0 (so pg15 and pg16 match, pg17 does NOT)
        Cve shared = saveCve("CVE-DIV-SHARED");
        saveMatch(shared.getId(),
            "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*",
            true, "14.0", null, null, "17.0");

        // pg15-only CVE — affects [15.0, 16.0)
        Cve pg15Only = saveCve("CVE-DIV-PG15");
        saveMatch(pg15Only.getId(),
            "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*",
            true, "15.0", null, null, "16.0");

        // pg16-specific CVE — affects [16.0, 17.0)
        Cve pg16Only = saveCve("CVE-DIV-PG16");
        saveMatch(pg16Only.getId(),
            "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*",
            true, "16.0", null, null, "17.0");

        // pg17-only CVE — mirrors live CVE-2026-6476 (17.x only) — affects [17.0, 18.0)
        Cve pg17Only = saveCve("CVE-DIV-PG17");
        saveMatch(pg17Only.getId(),
            "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*",
            true, "17.0", null, null, "18.0");

        List<Cve> pg15Results = matcher.findVulnerable(
            "cpe:2.3:a:postgresql:postgresql:15.6:*:*:*:*:*:*:*");
        List<Cve> pg16Results = matcher.findVulnerable(
            "cpe:2.3:a:postgresql:postgresql:16.0:*:*:*:*:*:*:*");
        List<Cve> pg17Results = matcher.findVulnerable(
            "cpe:2.3:a:postgresql:postgresql:17.6.1.029:*:*:*:*:*:*:*");

        Set<String> pg15Ids = pg15Results.stream().map(Cve::getCveId).collect(Collectors.toSet());
        Set<String> pg16Ids = pg16Results.stream().map(Cve::getCveId).collect(Collectors.toSet());
        Set<String> pg17Ids = pg17Results.stream().map(Cve::getCveId).collect(Collectors.toSet());

        // pg15 matches shared + pg15-only
        assertTrue(pg15Ids.contains("CVE-DIV-SHARED"), "pg15 must match shared CVE");
        assertTrue(pg15Ids.contains("CVE-DIV-PG15"), "pg15 must match pg15-only CVE");
        assertFalse(pg15Ids.contains("CVE-DIV-PG16"), "pg15 must NOT match pg16-only CVE");
        assertFalse(pg15Ids.contains("CVE-DIV-PG17"), "pg15 must NOT match pg17-only CVE");

        // pg16 matches shared + pg16-only
        assertTrue(pg16Ids.contains("CVE-DIV-SHARED"), "pg16 must match shared CVE");
        assertTrue(pg16Ids.contains("CVE-DIV-PG16"), "pg16 must match pg16-only CVE");
        assertFalse(pg16Ids.contains("CVE-DIV-PG15"), "pg16 must NOT match pg15-only CVE");
        assertFalse(pg16Ids.contains("CVE-DIV-PG17"), "pg16 must NOT match pg17-only CVE");

        // pg17 matches ONLY pg17-only (NOT the shared CVE which ends at 17.0 exclusive)
        assertFalse(pg17Ids.contains("CVE-DIV-SHARED"), "pg17 must NOT match shared CVE (range ends at 17.0 excl.)");
        assertFalse(pg17Ids.contains("CVE-DIV-PG15"), "pg17 must NOT match pg15-only CVE");
        assertFalse(pg17Ids.contains("CVE-DIV-PG16"), "pg17 must NOT match pg16-only CVE");
        assertTrue(pg17Ids.contains("CVE-DIV-PG17"), "pg17 must match pg17-only CVE (live shape: CVE-2026-6476)");

        // The three result sets are different — proves version-aware divergence
        assertNotEquals(pg15Ids, pg16Ids, "pg15 and pg16 matched sets must differ");
        assertNotEquals(pg16Ids, pg17Ids, "pg16 and pg17 matched sets must differ");
        assertNotEquals(pg15Ids, pg17Ids, "pg15 and pg17 matched sets must differ");
    }

    /**
     * Tighter check: pg16 and pg17 share no CVEs in a fixture that places shared
     * in the 14.0-17.0 range, proving that N-shared + 1-major-specific is explained
     * by version ranges, not by wildcard or broken matching.
     */
    @Test
    void pg16AndPg17_haveAtLeastOneMajorSpecificCve_notShared() {
        // Range strictly below pg17
        Cve belowPg17 = saveCve("CVE-BELOW-17");
        saveMatch(belowPg17.getId(),
            "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*",
            true, "15.0", null, null, "17.0");

        // pg17-only
        Cve abovePg16 = saveCve("CVE-ABOVE-16");
        saveMatch(abovePg16.getId(),
            "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*",
            true, "17.0", null, null, "18.0");

        Set<String> pg16Ids = matcher.findVulnerable(
            "cpe:2.3:a:postgresql:postgresql:16.4:*:*:*:*:*:*:*")
            .stream().map(Cve::getCveId).collect(Collectors.toSet());

        Set<String> pg17Ids = matcher.findVulnerable(
            "cpe:2.3:a:postgresql:postgresql:17.2:*:*:*:*:*:*:*")
            .stream().map(Cve::getCveId).collect(Collectors.toSet());

        assertTrue(pg16Ids.contains("CVE-BELOW-17"), "pg16 in range [15,17) must match");
        assertFalse(pg16Ids.contains("CVE-ABOVE-16"), "pg16 must not match [17,18) range");

        assertFalse(pg17Ids.contains("CVE-BELOW-17"), "pg17 must not match [15,17) range");
        assertTrue(pg17Ids.contains("CVE-ABOVE-16"), "pg17 in range [17,18) must match");

        // The two sets are disjoint — confirms major-specific divergence
        assertTrue(pg16Ids.stream().noneMatch(pg17Ids::contains),
            "pg16 and pg17 matched sets must be disjoint for these fixtures");
    }
}
