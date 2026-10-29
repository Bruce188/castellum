package io.castellum.cve;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

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

    // ─────────────────────────────────────────────────────────────────────
    // Fleet listing queries. Gate on ANY populated CVSS metric (v3.1, v3.0, or v2)
    // and order by the coalesced best-available score, mirroring CvssExtractor's
    // v3.1→v3.0→v2 precedence. The old derived finders gated on v3.1 alone, which
    // silently dropped (and mis-ordered as null) every CVE scored only under v3.0/v2.
    // The method names are retained (callers/tests reference them) but the @Query
    // overrides name-based derivation. ORDER BY is baked in, so callers pass an
    // unsorted Pageable (page+size only).
    // Native with explicit count queries: Spring Data's ANTLR HQL parser takes ~4s per
    // query here and can stall indefinitely deriving the count query at startup.
    // ─────────────────────────────────────────────────────────────────────

    @Query(nativeQuery = true,
        value = "SELECT c.* FROM cve c WHERE c.id IN (:ids) AND (c.cvss_v31_score IS NOT NULL OR c.cvss_v30_score IS NOT NULL OR c.cvss_v2_score IS NOT NULL) ORDER BY COALESCE(c.cvss_v31_score, c.cvss_v30_score, c.cvss_v2_score) DESC, c.cve_id ASC",
        countQuery = "SELECT count(*) FROM cve c WHERE c.id IN (:ids) AND (c.cvss_v31_score IS NOT NULL OR c.cvss_v30_score IS NOT NULL OR c.cvss_v2_score IS NOT NULL)")
    Page<Cve> findByIdInAndCvssV31ScoreIsNotNull(@Param("ids") Set<Long> ids, Pageable pageable);

    @Query(nativeQuery = true,
        value = "SELECT c.* FROM cve c WHERE c.id IN (:ids) AND COALESCE(c.cvss_v31_score, c.cvss_v30_score, c.cvss_v2_score) >= :minScore ORDER BY COALESCE(c.cvss_v31_score, c.cvss_v30_score, c.cvss_v2_score) DESC, c.cve_id ASC",
        countQuery = "SELECT count(*) FROM cve c WHERE c.id IN (:ids) AND COALESCE(c.cvss_v31_score, c.cvss_v30_score, c.cvss_v2_score) >= :minScore")
    Page<Cve> findByIdInAndCvssV31ScoreGreaterThanEqual(@Param("ids") Set<Long> ids,
                                                        @Param("minScore") BigDecimal minScore,
                                                        Pageable pageable);

    // v3-F1 — kevOnly fleet branch (cveId-IN only). Broadened to any-score, coalesced order.
    @Query(nativeQuery = true,
        value = "SELECT c.* FROM cve c WHERE c.cve_id IN (:cveIds) AND (c.cvss_v31_score IS NOT NULL OR c.cvss_v30_score IS NOT NULL OR c.cvss_v2_score IS NOT NULL) ORDER BY COALESCE(c.cvss_v31_score, c.cvss_v30_score, c.cvss_v2_score) DESC, c.cve_id ASC",
        countQuery = "SELECT count(*) FROM cve c WHERE c.cve_id IN (:cveIds) AND (c.cvss_v31_score IS NOT NULL OR c.cvss_v30_score IS NOT NULL OR c.cvss_v2_score IS NOT NULL)")
    Page<Cve> findByCveIdInAndCvssV31ScoreIsNotNull(@Param("cveIds") Set<String> cveIds, Pageable pageable);

    // kevOnly fleet branch — intersect the fleet-matched FK set (PK id IN) with the
    // KEV catalog (cveId IN), keeping paging at the DB level. Broadened to any-score,
    // coalesced order — same gate as findByIdInAndCvssV31ScoreIsNotNull above.
    @Query(nativeQuery = true,
        value = "SELECT c.* FROM cve c WHERE c.id IN (:ids) AND c.cve_id IN (:cveIds) AND (c.cvss_v31_score IS NOT NULL OR c.cvss_v30_score IS NOT NULL OR c.cvss_v2_score IS NOT NULL) ORDER BY COALESCE(c.cvss_v31_score, c.cvss_v30_score, c.cvss_v2_score) DESC, c.cve_id ASC",
        countQuery = "SELECT count(*) FROM cve c WHERE c.id IN (:ids) AND c.cve_id IN (:cveIds) AND (c.cvss_v31_score IS NOT NULL OR c.cvss_v30_score IS NOT NULL OR c.cvss_v2_score IS NOT NULL)")
    Page<Cve> findByIdInAndCveIdInAndCvssV31ScoreIsNotNull(@Param("ids") Set<Long> ids,
                                                           @Param("cveIds") Collection<String> cveIds,
                                                           Pageable pageable);

    /**
     * Lightweight projection for STIX bundle assembly: selects only cveId and description,
     * leaving the heavy raw_json column out of the result set to bound heap usage.
     */
    @Query("SELECT c.cveId AS cveId, c.description AS description FROM Cve c")
    List<CveStixView> findAllStixViews();
}
