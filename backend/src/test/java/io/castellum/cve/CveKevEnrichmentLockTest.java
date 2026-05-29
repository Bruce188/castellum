package io.castellum.cve;

import io.castellum.cve.CveEnrichmentService.Enrichment;
import io.castellum.risk.Criticality;
import io.castellum.risk.EpssScoreRepository;
import io.castellum.risk.KevEntry;
import io.castellum.risk.KevEntryRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.context.annotation.Import;

import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * AC4 — KEV flag/count regression lock.
 *
 * <p>Proves the {@link CveEnrichmentService} KEV join is correct:
 * <ul>
 *   <li>A CVE that IS in the KEV catalog flips {@code kev=true} and increments the KEV count.</li>
 *   <li>A CVE that is NOT in the KEV catalog stays {@code kev=false}.</li>
 * </ul>
 *
 * <p>This test is mocked at the repository level — it does NOT require a live DB or network
 * (pure @DataJpaTest with H2). When the corpus is populated with KEV-listed CVEs (e.g. after
 * the full NVD backfill) the badge will appear; this test guards the join so the badge never
 * silently breaks.
 */
@DataJpaTest
@Import({CveEnrichmentService.class})
class CveKevEnrichmentLockTest {

    @Autowired
    CveEnrichmentService enrichmentService;

    @Autowired
    CveRepository cveRepository;

    @Autowired
    KevEntryRepository kevRepo;

    @Autowired
    EpssScoreRepository epssRepo;

    private Cve saveCve(String cveId) {
        Cve cve = new Cve();
        cve.setCveId(cveId);
        cve.setLastModified(Instant.now());
        cve.setRawJson("{}");
        cve.setFetchedAt(Instant.now());
        return cveRepository.save(cve);
    }

    private KevEntry saveKev(String cveId) {
        KevEntry k = new KevEntry();
        k.setCveId(cveId);
        k.setDateAdded(LocalDate.of(2024, 1, 1));
        k.setIngestedAt(Instant.now());
        return kevRepo.save(k);
    }

    /**
     * A CVE that IS in the KEV catalog enriches with kev=true.
     * The batch enrich path covers the N-CVE case (fleet listing).
     */
    @Test
    void kevListedCve_enrichesAsKevTrue() {
        Cve cve = saveCve("CVE-KEV-LISTED");
        saveKev("CVE-KEV-LISTED");

        Map<String, Enrichment> enriched = enrichmentService.enrich(List.of(cve), Criticality.MEDIUM);

        Enrichment e = enriched.get("CVE-KEV-LISTED");
        assertNotNull(e, "Enrichment must be present for saved CVE");
        assertEquals(Boolean.TRUE, e.kev(), "CVE in KEV catalog must enrich with kev=true");
    }

    /**
     * A CVE that is NOT in the KEV catalog enriches with kev=false.
     */
    @Test
    void nonKevCve_enrichesAsKevFalse() {
        Cve cve = saveCve("CVE-NOT-KEV");
        // deliberately do NOT save a KEV entry

        Map<String, Enrichment> enriched = enrichmentService.enrich(List.of(cve), Criticality.MEDIUM);

        Enrichment e = enriched.get("CVE-NOT-KEV");
        assertNotNull(e, "Enrichment must be present for saved CVE");
        assertEquals(Boolean.FALSE, e.kev(), "CVE not in KEV catalog must enrich with kev=false");
    }

    /**
     * Batch path: a mix of KEV-listed and non-listed CVEs — each row gets the correct flag.
     * Proves the batch enrichment path (used by fleet listing) preserves per-CVE accuracy.
     */
    @Test
    void batchEnrich_mixedKevMembership_eachRowCorrect() {
        Cve kev1 = saveCve("CVE-KEV-MIX-A");
        Cve kev2 = saveCve("CVE-KEV-MIX-B");
        Cve nonKev = saveCve("CVE-NONKEV-MIX-C");

        saveKev("CVE-KEV-MIX-A");
        saveKev("CVE-KEV-MIX-B");
        // CVE-NONKEV-MIX-C intentionally omitted from KEV

        Map<String, Enrichment> enriched = enrichmentService.enrich(
            List.of(kev1, kev2, nonKev), Criticality.MEDIUM);

        assertEquals(Boolean.TRUE, enriched.get("CVE-KEV-MIX-A").kev(), "CVE-KEV-MIX-A must be kev=true");
        assertEquals(Boolean.TRUE, enriched.get("CVE-KEV-MIX-B").kev(), "CVE-KEV-MIX-B must be kev=true");
        assertEquals(Boolean.FALSE, enriched.get("CVE-NONKEV-MIX-C").kev(), "CVE-NONKEV-MIX-C must be kev=false");

        // Count of KEV-true entries equals the 2 saved KEV entries — not 3
        long kevCount = enriched.values().stream().filter(e -> Boolean.TRUE.equals(e.kev())).count();
        assertEquals(2, kevCount, "Exactly 2 of 3 CVEs must be KEV-listed");
    }

    /**
     * Single-row path (enrichOne — used by detail endpoint): KEV-listed CVE
     * flips kev=true; non-listed stays false.
     */
    @Test
    void enrichOne_kevListedFlipsTrue_nonListedStaysFalse() {
        Cve listed = saveCve("CVE-ONE-LISTED");
        Cve notListed = saveCve("CVE-ONE-UNLISTED");
        saveKev("CVE-ONE-LISTED");

        Enrichment e1 = enrichmentService.enrichOne(listed, Criticality.MEDIUM);
        Enrichment e2 = enrichmentService.enrichOne(notListed, Criticality.MEDIUM);

        assertEquals(Boolean.TRUE, e1.kev(), "enrichOne: listed CVE must be kev=true");
        assertEquals(Boolean.FALSE, e2.kev(), "enrichOne: unlisted CVE must be kev=false");
    }
}
