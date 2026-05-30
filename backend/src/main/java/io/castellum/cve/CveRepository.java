package io.castellum.cve;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.Set;

public interface CveRepository extends JpaRepository<Cve, Long> {

    Optional<Cve> findByCveId(String cveId);

    @Query("SELECT MAX(c.lastModified) FROM Cve c")
    Optional<Instant> findMaxLastModified();

    /**
     * Earliest calendar year of any {@code published} timestamp in the corpus.
     * Returns empty when no CVE has a non-null published timestamp.
     * Used by the coverage endpoint (AC3) to detect thin / skewed corpora.
     * Uses {@code EXTRACT(YEAR FROM ...)} which is portable across PostgreSQL and H2
     * (Hibernate 6 / Spring Boot 3.x).
     */
    @Query("SELECT CAST(MIN(EXTRACT(YEAR FROM c.published)) AS integer) FROM Cve c WHERE c.published IS NOT NULL")
    Optional<Integer> findEarliestPublishedYear();

    /**
     * Latest calendar year of any {@code published} timestamp in the corpus.
     * Returns empty when no CVE has a non-null published timestamp.
     * Used by the coverage endpoint (AC3).
     */
    @Query("SELECT CAST(MAX(EXTRACT(YEAR FROM c.published)) AS integer) FROM Cve c WHERE c.published IS NOT NULL")
    Optional<Integer> findLatestPublishedYear();

    Page<Cve> findByCvssV31ScoreIsNotNull(Pageable pageable);

    Page<Cve> findByCvssV31ScoreGreaterThanEqual(BigDecimal minScore, Pageable pageable);

    Page<Cve> findByIdInAndCvssV31ScoreIsNotNull(Set<Long> ids, Pageable pageable);

    Page<Cve> findByIdInAndCvssV31ScoreGreaterThanEqual(Set<Long> ids, BigDecimal minScore, Pageable pageable);

    // v3-F1 — kevOnly fleet branch. Spring Data JPA generates the IN-clause and
    // CvssV31Score IS NOT NULL predicate; no @Query annotation needed.
    Page<Cve> findByCveIdInAndCvssV31ScoreIsNotNull(Set<String> cveIds, Pageable pageable);

    // kevOnly fleet branch — intersect the fleet-matched FK set (PK id IN) with the
    // KEV catalog (cveId IN), keeping paging at the DB level. Same derivation
    // convention as findByIdInAndCvssV31ScoreIsNotNull above.
    Page<Cve> findByIdInAndCveIdInAndCvssV31ScoreIsNotNull(Set<Long> ids, Collection<String> cveIds, Pageable pageable);

    /**
     * Lightweight projection for STIX bundle assembly: selects only cveId and description,
     * leaving the heavy raw_json column out of the result set to bound heap usage.
     */
    @Query("SELECT c.cveId AS cveId, c.description AS description FROM Cve c")
    List<CveStixView> findAllStixViews();
}
