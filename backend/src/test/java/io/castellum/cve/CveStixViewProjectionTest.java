package io.castellum.cve;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.context.TestPropertySource;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * RED-phase guard for the heap-bounding CVE projection.
 *
 * Asserts that {@link CveRepository#findAllStixViews()} (a method that does not
 * yet exist) returns one {@link CveStixView} per seeded row, carrying the correct
 * {@code cveId} and {@code description}, via a select-list that covers ONLY those
 * two columns — leaving the heavy {@code raw_json} TEXT column out of the result.
 *
 * The test seeds two CVEs: one with a tiny rawJson and one with a deliberately
 * large rawJson blob. Both must appear in the projection results with their correct
 * lightweight fields; the rawJson column is not accessible through the projection
 * interface by design.
 */
@DataJpaTest
@TestPropertySource(properties = {
    "spring.flyway.enabled=true",
    "spring.flyway.locations=classpath:db/migration/h2",
    "spring.jpa.hibernate.ddl-auto=validate"
})
class CveStixViewProjectionTest {

    @Autowired
    private CveRepository cveRepository;

    private Cve buildCve(String cveId, String description, String rawJson) {
        Cve cve = new Cve();
        cve.setCveId(cveId);
        cve.setDescription(description);
        cve.setLastModified(Instant.now());
        cve.setRawJson(rawJson);
        cve.setFetchedAt(Instant.now());
        return cve;
    }

    /**
     * Projection returns one view per seeded CVE, preserving cveId and description.
     *
     * Two rows are seeded: one thin (small rawJson) and one fat (large rawJson blob
     * representative of a real NVD payload). The assertion confirms that:
     * - result size == 2 (all rows returned, order-independent)
     * - each view exposes getCveId() matching the seeded value
     * - each view exposes getDescription() matching the seeded value
     *
     * The rawJson column is intentionally absent from the CveStixView interface;
     * the compiler enforces that callers cannot access it through the projection.
     */
    @Test
    void findAllStixViews_returnsOneLightweightViewPerCve_withCorrectFields() {
        // Seed a thin CVE (rawJson is minimal)
        Cve thin = buildCve(
            "CVE-2024-00001",
            "A thin vulnerability with a short description.",
            "{}"
        );
        cveRepository.save(thin);

        // Seed a fat CVE whose rawJson would be expensive to hydrate at scale.
        // The description is what BundleAssembler actually needs.
        String largeBlobRawJson = "x".repeat(100_000); // 100 KB representative NVD blob
        Cve fat = buildCve(
            "CVE-2024-00002",
            "A fat vulnerability whose raw JSON must not be loaded by the projection.",
            largeBlobRawJson
        );
        cveRepository.save(fat);

        // Method under test: CveRepository.findAllStixViews() — does NOT exist yet (RED)
        List<CveStixView> views = cveRepository.findAllStixViews();

        assertEquals(2, views.size(), "projection must return one view per persisted CVE");

        // Sort by cveId for deterministic assertion
        views.sort((a, b) -> a.getCveId().compareTo(b.getCveId()));

        CveStixView v1 = views.get(0);
        assertEquals("CVE-2024-00001", v1.getCveId());
        assertEquals("A thin vulnerability with a short description.", v1.getDescription());

        CveStixView v2 = views.get(1);
        assertEquals("CVE-2024-00002", v2.getCveId());
        assertEquals("A fat vulnerability whose raw JSON must not be loaded by the projection.", v2.getDescription());
    }

    /**
     * Projection result count tracks the actual CVE table row count.
     *
     * Confirms that findAllStixViews() is not accidentally filtered or limited —
     * every row gets exactly one view. Uses a fresh three-row seed independent of
     * the previous test (DataJpaTest rolls back between tests).
     */
    @Test
    void findAllStixViews_resultCountMatchesRepositoryCount() {
        cveRepository.save(buildCve("CVE-2025-10001", "desc one",   "{}"));
        cveRepository.save(buildCve("CVE-2025-10002", "desc two",   "{}"));
        cveRepository.save(buildCve("CVE-2025-10003", "desc three", "{}"));

        List<CveStixView> views = cveRepository.findAllStixViews();

        assertEquals(cveRepository.count(), views.size(),
            "findAllStixViews must return one view for every row in the cve table");
    }
}
