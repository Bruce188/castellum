package io.castellum.risk;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

public interface KevEntryRepository extends JpaRepository<KevEntry, Long> {
    Optional<KevEntry> findByCveId(String cveId);

    boolean existsByCveId(String cveId);

    List<KevEntry> findAllByCveIdIn(Collection<String> cveIds);

    @Query("SELECT MAX(k.ingestedAt) FROM KevEntry k")
    Optional<Instant> findMaxIngestedAt();

    /**
     * Projects only the {@code cve_id} column for the KEV catalog. Used by the
     * {@code kevOnly=true} fleet branch to build a {@link java.util.Set} of
     * KEV-listed cveIds without loading every column of every row (~1.2k today,
     * growing) — addresses review-v44 perf-tuner B3.
     */
    @Query("SELECT k.cveId FROM KevEntry k")
    List<String> findAllCveIds();

    /**
     * Count of KEV catalog entries whose {@code cve_id} also exists in the local
     * NVD corpus ({@code cve} table). Used by the coverage endpoint (AC3) to surface
     * "KEV-in-corpus" count without loading every CVE row. Returns 0 when the corpus
     * is empty or no KEV entries overlap.
     */
    @Query("SELECT COUNT(k) FROM KevEntry k WHERE EXISTS " +
           "(SELECT 1 FROM Cve c WHERE c.cveId = k.cveId)")
    long countKevInCorpus();
}
